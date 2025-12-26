#!/bin/bash

cargo build --release

cp target/i686-pc-windows-gnu/release/dinput8.dll "/home/$USER/.local/share/Steam/steamapps/common/Lego Star Wars Saga/dinput8.dll"