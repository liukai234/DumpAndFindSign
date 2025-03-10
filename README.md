## Build

cmake -G Ninja -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

cmake --build build

## Run

rundll32.exe \path\to\dumper.dll,Inject <0x window_handler> OR Inject directly