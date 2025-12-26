use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use quote::{format_ident, quote};
use std::fs;

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // read functions from CSV
    let mut func_rdr = csv::Reader::from_path("functions.csv").expect("Failed to open functions.csv");
    let mut functions = Vec::new();
    for result in func_rdr.records() {
        let record = result.expect("Failed to read record");
        let func_name = record.get(0).expect("No function name").to_string();
        let func_addr = record.get(1).expect("No function address").to_string();
        let func_addr = format!("0x{}", func_addr);
        let func_sig = record
            .get(2)
            .expect("No function signature")
            .to_string()
            .replace("\\", ""); // remove escapes
        functions.push((func_name, func_addr, func_sig));
    }

    // create hashmap from function name to address
    let func_addr_map: HashMap<String, String> = functions
        .iter()
        .map(|(name, addr, _)| (name.clone(), addr.clone()))
        .collect();


    let mut sym_rdr = csv::Reader::from_path("symbols.csv").expect("Failed to open symbols.csv");
    let mut symbols = Vec::new();
    for result in sym_rdr.records() {
        let record = result.expect("Failed to read record");
        let sym_name = record.get(0).expect("No symbol name").to_string();
        let sym_addr = record.get(1).expect("No symbol address").to_string();
        let sym_addr = format!("0x{}", sym_addr);
        let sym_type = record.get(2).expect("No symbol type").to_string();
        if sym_type != "Data Label" {
            continue;
        }

        let sym_data_type = record.get(3).expect("No symbol data type").to_string();
        symbols.push((sym_name, sym_addr, sym_data_type));
    }

    // create hashmap from symbol name to address
    let sym_addr_map: HashMap<String, String> = symbols
        .iter()
        .map(|(name, addr, _)| (name.clone(), addr.clone()))
        .collect();

    // make temp header that begins with the content of LEGOStarWarsSaga.exe.h
    // plus the function declarations from the CSV
    let mut header_content =
        std::fs::read_to_string("LEGOStarWarsSaga.exe.h").expect("Failed to read header file");

    
    header_content = header_content.replace("float10", "");
    header_content = header_content.replace("typedef unsigned char    bool;", "#include <stdbool.h>");
    header_content = format!("typedef unsigned long pointer32;\n{}", header_content);
    for (name, _, sig) in &functions {
        if sig.contains("`")
            || sig.contains("'")
            || sig.contains("this")
            || sig.contains("~")
            || sig.contains("thunk")
            || sig.contains("float10")
            || sig.contains("_func")
            || sig.contains(":")
            || sig.contains("operator")
            || sig.contains("[")
            || sig.contains("]")
            || sig.contains("@")
            || sig.contains("_PtFuncCompare")
            || sig.contains("_EXCEPTION_DISPOSITION")
            || sig.contains("Tokens")
            || sig.contains("getDataIndirectType")
            || sig.contains("write_char")
            || sig.contains("write_multi_char")
        {
            // manual exceptions for problematic signatures
            continue;
        }

        // hopefully this doesn't break on some weird edge case
        let modified_sig = sig.replace(name, &format!("STUB_{name}"));
        header_content.push_str(&format!("{modified_sig};\n"));
    }

    for (name, _, data_type) in &symbols {
        if data_type.contains("pointer") || data_type.contains("[") || data_type.contains("]") || data_type.contains("IconResource") || data_type.contains("TerminatedCString") {
            // skip problematic types for now
            continue;
        }

        if name.contains("?") {
            // skip problematic names for now
            continue;
        }

        header_content.push_str(&format!(
            "{} STUB_{};\n",
            data_type,
            name
        ));
    }

    let out_header_path = out_path.join("out.h");
    std::fs::write(&out_header_path, header_content)
        .expect("Failed to write temporary header file");

    let bindings = bindgen::Builder::default()
        .header(out_header_path.display().to_string())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    // let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    // bindings
    //     .write_to_file(out_path.join("bindings.rs"))
    //     .expect("Couldn't write bindings!");

    // println!("cargo:rustc-link-arg=-Wl,--defsym={}={}", "__DrawMenuEntryEx", "0x0050f740");

    // // set image base
    // println!("cargo:rustc-link-arg=-Wl,--image-base,0x00400000");

    let bindings_str = bindings.to_string();
    let ast = syn::parse_file(&bindings_str).expect("Failed to parse bindings");


    let mut wrappers = String::new();
    ast.items.iter().for_each(|item| {
        if let syn::Item::ForeignMod(fmod) = item {
            fmod.items.iter().for_each(|foreign_item| {
                if let syn::ForeignItem::Fn(func) = foreign_item {
                    let stub_name = &func.sig.ident;
                    let func_args = &func.sig.inputs;
                    let func_ret = &func.sig.output;

                    let func_name = stub_name.to_string().replace("STUB_", "");
                    let func_name_ident = syn::Ident::new(&func_name, stub_name.span());
                    let func_addr = func_addr_map
                        .get(&func_name)
                        .expect("Function address not found");

                    // turn addr into expr
                    let func_addr_expr = syn::parse_str::<syn::Expr>(&func_addr).expect("Failed to parse function address");

                    let func_sym_ident = format_ident!("SYM_{}", func_name_ident);

                    let wrapper_code = quote! {
                        static mut #func_sym_ident: *const std::os::raw::c_void = unsafe { std::mem::transmute(#func_addr_expr as usize) };

                        #[unsafe(naked)]
                        #[unsafe(no_mangle)]
                        pub extern "C" fn #func_name_ident( #func_args ) #func_ret {
                            std::arch::naked_asm!("jmp [{}]", sym #func_sym_ident);
                        }
                    };

                    wrappers.push_str(&wrapper_code.to_string());
                    wrappers.push_str("\n");
                } else if let syn::ForeignItem::Static(stat) = foreign_item {
                    let stub_name = &stat.ident;

                    let sym_name = stub_name.to_string().replace("STUB_", "");
                    let sym_ty = &stat.ty;
                    let sym_addr = sym_addr_map
                        .get(&sym_name)
                        .expect("Symbol address not found");

                    let sym_name = format_ident!("{}", sym_name);

                    // turn addr into expr
                    let sym_addr_expr = syn::parse_str::<syn::Expr>(&sym_addr).expect("Failed to parse symbol address");

                    let wrapper_code = quote! {
                        pub const #sym_name: *mut #sym_ty = unsafe { std::mem::transmute(#sym_addr_expr as usize) };
                    };

                    wrappers.push_str(&wrapper_code.to_string());
                    wrappers.push_str("\n");
                }
            });
        } 
    });

    let mut final_output = bindings_str;
    final_output.push_str(&wrappers);

    fs::write(out_path.join("bindings.rs"), final_output)
        .expect("Couldn't write bindings!");
}
