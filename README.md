# my pwn tookit

## tools

```shell
.
├── Makefile            # define some Shortcuts
├── .helper             # store onegadget rop info in `pickle format`
├── README.md
├── config.py           # binary path & initial work
├── helper
│   ├── arg.py          # arg parser
│   ├── elf_loader.py   # 
│   ├── exp.py          # exp template
│   ├── heap            # heap_helper => common heap tech
│   │   └── heap.py 
│   ├── qemu            # qemu helper
│   │   └── qemu.py
│   └── utils.py        
├── main.py             # write your exp here!
└── tools
    ├── aslr        # enable/disable aslr in your system
    ├── asm         # record some asm knowledge
    ├── checksec    # checksec, but user friendly
    ├── exp_decoder # convert wp into my own format
    ├── ida         # open ida-32, usage: ida [binary] &
    ├── ida-server  # open ida-server -- infer 32/64bit by config.py
    ├── malloc      # download source 
    ├── pwn_clean   # do clean job
    ├── setcontext  # 
    └── update.sh   # find newest file in `.target` folder and update info in config.py
```