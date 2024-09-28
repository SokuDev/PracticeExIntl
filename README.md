# PracticeExIntl

Internationalization tool for PracticeEx v2.1.0 (an advanced Pratice Mode mod for Touhou 12.3).

Todo: document

## Prune fonts

To avoid slowing PracticeEx down or [failing to render texts because too many glyphs are loaded](https://github.com/ocornut/imgui/blob/master/docs/FONTS.md#4-font-atlas-texture-fails-to-upload-to-gpu), the fonts can be pruned and include only ASCII and other needed glyphs:

```bash
fontforge -script make_fony.py SOURCE-FONT SCALE TRANSLATION-CSV OUTPUT-OTF-OR-TTF-PATH
```

For example:

```bash
fontforge -script make_font.py simhei.ttf 1 OptionsRight.csv OptionsRight.otf
```

To make the text bigger (especially in `OptionsLeft` and `Title`), you can use bigger SCALE value to generate the font.

## Build the mod
Requires CMake, git and the VisualStudio compiler (MSVC).
Both git and cmake needs to be in the PATH environment variable.

All the following commands are to be run inside the visual studio 32bits compiler
command prompt (called `x86 Native Tools Command Prompt for VS 20XX` in the start menu), unless stated otherwise.

## Initialization
First go inside the folder you want the repository to be in.
In this example it will be C:\Users\PinkySmile\SokuProjects but remember to replace this
with the path for your machine. If you don't want to type the full path, you can drag and
drop the folder onto the console.

`cd C:\Users\PinkySmile\SokuProjects`

Now let's download the repository and initialize it for the first time
```
git clone https://github.com/SokuDev/PracticeExIntl
cd PracticeExIntl
git submodule init
git submodule update
mkdir build
cd build
cmake .. -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Debug
```
Note that if you want to build in Release, you should replace `-DCMAKE_BUILD_TYPE=Debug` with `-DCMAKE_BUILD_TYPE=Release`.

## Compiling
Now, to build the mod, go to the build directory (if you did the previous step you already are)
`cd C:\Users\PinkySmile\SokuProjects\PracticeExIntl\build` and invoke the compiler by running `cmake --build . --target PracticeExIntl`. If you change the name of the mod (in the add_library statement in CMakeLists.txt), you will need to replace 'PracticeExIntl' by the name of your mod in the previous command.

You should find the resulting PracticeExIntl.dll mod inside the build folder that can be to SWRSToys.ini.
In my case, I would add this line to it `PracticeExIntl=C:/Users/PinkySmile/SokuProjects/PracticeExIntl/build/PracticeExIntl.dll`.
