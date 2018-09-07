# Hello World in 32-bit Assembly

## Prerequisites
  * Linux
  * The C++ IDE [juCi++](https://github.com/cppit/jucipp)

## Installing dependencies

### Debian based distributions
`sudo apt-get install binutils nasm`

### Arch Linux based distributions
`sudo pacman -S binutils nasm`

## Compiling and running
The `cp` command below adds assembly syntax highlighting and keyword completion to juCi++.
```sh
git clone https://gitlab.com/ntnu-tdat3020/assembly-example
sudo cp assembly-example/asm.lang /usr/share/gtksourceview-3.0/language-specs/
juci assembly-example
```

The `-f elf64` flag below tells the compiler that the source uses 64-bit instructions
### Alternative 1
In a terminal:
```sh
cd assembly-example
nasm -f elf64 hello.s  # Compile source to object file that contains machine code
                       # and usually also references to functions or variables found
                       # in other object files or libraries.
ld hello.o -o hello    # Link object file and create executable. Normally, 
                       # the machine code of several object files are here combined into 
                       # one executable, but references to dynamic libraries are kept.
./hello                # Run executable
```

### Alternative 2
Choose Run Command in the juCi++ Project menu, and run the following command:
```sh
nasm -f elf64 hello.s && ld hello.o -o hello && ./hello
```

Note: if you make changes to the `hello.s` source file, remember to save it before running the above command.
