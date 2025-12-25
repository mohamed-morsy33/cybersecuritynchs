# Terminal

Here's an interactive terminal with full Linux commands:

<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css" />

<div id="terminal-container" class="power-on">
    <div class="terminal-header">
        <div class="terminal-buttons">
            <div class="terminal-button close"></div>
            <div class="terminal-button minimize"></div>
            <div class="terminal-button maximize"></div>
        </div>
    </div>
    <div class="terminal-content"></div>
</div>

<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
<script>
(function() {
    setTimeout(function() {
        const container = document.querySelector('.terminal-content');
        
        if (!container || typeof Terminal === 'undefined') {
            console.error('Terminal setup failed');
            return;
        }
        
        const term = new Terminal({
            cursorBlink: true,
            fontSize: 15,
            fontFamily: '"Fira Code", "Cascadia Code", "JetBrains Mono", Consolas, Monaco, monospace',
            fontWeight: 400,
            fontWeightBold: 700,
            lineHeight: 1.2,
            letterSpacing: 0,
            theme: {
                background: '#1e1e1e',
                foreground: '#cccccc',
                cursor: '#00ff00',
                cursorAccent: '#1e1e1e',
                selection: '#264f78',
                black: '#000000',
                red: '#cd3131',
                green: '#0dbc79',
                yellow: '#e5e510',
                blue: '#2472c8',
                magenta: '#bc3fbc',
                cyan: '#11a8cd',
                white: '#e5e5e5',
                brightBlack: '#666666',
                brightRed: '#f14c4c',
                brightGreen: '#23d18b',
                brightYellow: '#f5f543',
                brightBlue: '#3b8eea',
                brightMagenta: '#d670d6',
                brightCyan: '#29b8db',
                brightWhite: '#ffffff'
            },
            allowTransparency: true
        });
        
        term.open(container);
        
        // Enhanced file system
        let fileSystem = {
            '/': {
                'home': {
                    'user': {
                        'documents': {
                            'notes.txt': 'These are my personal notes.\nRemember to study for the exam!',
                            'todo.txt': '1. Finish homework\n2. Practice CTF\n3. Read security blog'
                        },
                        'projects': {
                            'cybersec': {
                                'README.md': '# CyberSec Project\n\nThis is a cybersecurity learning project.',
                                'exploit.py': '#!/usr/bin/env python3\nprint("Hello, hacker!")'
                            },
                            'web': {
                                'index.html': '<html><body>Hello World</body></html>'
                            }
                        },
                        'scripts': {
                            'hello.sh': '#!/bin/bash\necho "Hello, World!"'
                        }
                    }
                },
                'etc': {
                    'hosts': '127.0.0.1 localhost\n::1 localhost',
                    'passwd': 'root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash'
                },
                'var': {
                    'log': {
                        'syslog': 'System log entries...'
                    }
                },
                'tmp': {}
            }
        };
        
        let currentPath = '/home/user';
        let currentLine = '';
        let commandHistory = [];
        let historyIndex = -1;
        let vimMode = false;
        let vimBuffer = [];
        let vimCurrentLine = 0;
        let vimFilename = '';
        let vimInsertMode = false;
        let vimCommandMode = false;
        let vimCommandLine = '';
        
        term.writeln('\x1b[1;32m╔═══════════════════════════════════════════════╗\x1b[0m');
        term.writeln('\x1b[1;32m║    Welcome to Interactive Terminal Demo       ║\x1b[0m');
        term.writeln('\x1b[1;32m╚═══════════════════════════════════════════════╝\x1b[0m');
        term.writeln('');
        term.writeln('Type \x1b[1;36mhelp\x1b[0m for available commands.');
        term.writeln('');
        writePrompt();
        
        function writePrompt() {
            term.write(`\x1b[1;32muser@nchscyber\x1b[0m:\x1b[1;34m${currentPath}\x1b[0m$ `);
        }
        
        function getObjectAtPath(path) {
            if (path === '/') return fileSystem['/'];
            
            const parts = path.split('/').filter(p => p);
            let current = fileSystem['/'];
            
            for (const part of parts) {
                if (!current || current[part] === undefined) {
                    return null;
                }
                current = current[part];
            }
            return current;
        }
        
        function resolvePath(path) {
            if (path.startsWith('/')) {
                return path;
            }
            
            if (path === '~') {
                return '/home/user';
            }
            
            if (path.startsWith('~/')) {
                return '/home/user/' + path.substring(2);
            }
            
            let result = currentPath;
            const parts = path.split('/');
            
            for (const part of parts) {
                if (part === '..') {
                    const segments = result.split('/').filter(p => p);
                    segments.pop();
                    result = '/' + segments.join('/');
                    if (result === '/') result = '/';
                } else if (part === '.' || part === '') {
                    continue;
                } else {
                    result = result + (result.endsWith('/') ? '' : '/') + part;
                }
            }
            
            return result;
        }
        
        function isDirectory(obj) {
            return obj !== null && typeof obj === 'object' && !Array.isArray(obj);
        }
        
        function processCommand(cmd) {
            // Handle pipes
            if (cmd.includes('|')) {
                const parts = cmd.split('|').map(p => p.trim());
                let output = null;
                
                for (let i = 0; i < parts.length; i++) {
                    if (i === 0) {
                        output = executeCommand(parts[i]);
                    } else {
                        output = executeCommand(parts[i], output);
                    }
                }
                return;
            }
            
            // Handle output redirection
            if (cmd.includes('>')) {
                const parts = cmd.split('>').map(p => p.trim());
                const output = executeCommand(parts[0]);
                
                if (output && parts[1]) {
                    const filepath = resolvePath(parts[1]);
                    const pathParts = filepath.split('/').filter(p => p);
                    const filename = pathParts.pop();
                    const dirPath = '/' + pathParts.join('/');
                    
                    const dir = getObjectAtPath(dirPath || '/');
                    if (dir && isDirectory(dir)) {
                        dir[filename] = output.join('\n');
                        term.writeln(`\x1b[32mOutput written to ${parts[1]}\x1b[0m`);
                    } else {
                        term.writeln(`\x1b[31mError: Directory not found\x1b[0m`);
                    }
                }
                return;
            }
            
            executeCommand(cmd);
        }
        
        function executeCommand(cmd, pipeInput = null) {
            const parts = cmd.split(' ').filter(p => p);
            const command = parts[0];
            const args = parts.slice(1);
            
            const commands = {
                'help': () => {
                    const output = [
                        '\x1b[1;33mAvailable Commands:\x1b[0m',
                        '  \x1b[36mhelp\x1b[0m       - Show this help message',
                        '  \x1b[36mclear\x1b[0m      - Clear the terminal screen',
                        '  \x1b[36mecho\x1b[0m       - Print text to terminal',
                        '  \x1b[36mdate\x1b[0m       - Show current date and time',
                        '  \x1b[36mpwd\x1b[0m        - Print working directory',
                        '  \x1b[36mls\x1b[0m         - List directory contents',
                        '  \x1b[36mcd\x1b[0m         - Change directory',
                        '  \x1b[36mmkdir\x1b[0m      - Create a new directory',
                        '  \x1b[36mrmdir\x1b[0m      - Remove empty directory',
                        '  \x1b[36mtouch\x1b[0m      - Create a new file',
                        '  \x1b[36mcat\x1b[0m        - Display file contents',
                        '  \x1b[36mrm\x1b[0m         - Remove file or directory',
                        '  \x1b[36mmv\x1b[0m         - Move/rename files',
                        '  \x1b[36mcp\x1b[0m         - Copy files',
                        '  \x1b[36mgrep\x1b[0m       - Search for patterns',
                        '  \x1b[36mfind\x1b[0m       - Find files',
                        '  \x1b[36mwhoami\x1b[0m     - Display current user',
                        '  \x1b[36muname\x1b[0m      - Display system information',
                        '  \x1b[36mvim\x1b[0m        - Text editor',
                        '',
                        '\x1b[1;33mAdvanced:\x1b[0m',
                        '  Use \x1b[36m|\x1b[0m for pipes: ls | grep test',
                        '  Use \x1b[36m>\x1b[0m for output: echo hello > file.txt'
                    ];
                    output.forEach(line => term.writeln(line));
                    return output;
                },
                
                'clear': () => {
                    term.clear();
                    return [];
                },
                
                'date': () => {
                    const output = [new Date().toString()];
                    term.writeln(output[0]);
                    return output;
                },
                
                'pwd': () => {
                    const output = [currentPath];
                    term.writeln(output[0]);
                    return output;
                },
                
                'whoami': () => {
                    const output = ['user'];
                    term.writeln(output[0]);
                    return output;
                },
                
                'uname': () => {
                    const output = args[0] === '-a' 
                        ? ['Linux nchscyber 5.15.0 #1 SMP x86_64 GNU/Linux']
                        : ['Linux'];
                    term.writeln(output[0]);
                    return output;
                },
                
                'ls': () => {
                    const path = args[0] ? resolvePath(args[0]) : currentPath;
                    const obj = getObjectAtPath(path);
                    const output = [];
                    
                    if (!obj) {
                        term.writeln(`\x1b[31mls: ${args[0]}: No such file or directory\x1b[0m`);
                        return [];
                    }
                    
                    if (!isDirectory(obj)) {
                        term.writeln(`\x1b[31mls: ${args[0]}: Not a directory\x1b[0m`);
                        return [];
                    }
                    
                    const entries = Object.keys(obj);
                    if (entries.length === 0) {
                        return [];
                    }
                    
                    entries.forEach(entry => {
                        if (isDirectory(obj[entry])) {
                            term.writeln(`\x1b[1;34m${entry}/\x1b[0m`);
                            output.push(entry + '/');
                        } else {
                            term.writeln(`\x1b[37m${entry}\x1b[0m`);
                            output.push(entry);
                        }
                    });
                    
                    return output;
                },
                
                'cd': () => {
                    if (args.length === 0 || args[0] === '~') {
                        currentPath = '/home/user';
                        return [];
                    }
                    
                    const newPath = resolvePath(args[0]);
                    const obj = getObjectAtPath(newPath);
                    
                    if (obj && isDirectory(obj)) {
                        currentPath = newPath;
                    } else {
                        term.writeln(`\x1b[31mcd: ${args[0]}: No such directory\x1b[0m`);
                    }
                    return [];
                },
                
                'mkdir': () => {
                    if (args.length === 0) {
                        term.writeln('\x1b[31mUsage: mkdir <directory_name>\x1b[0m');
                        return [];
                    }
                    
                    const path = resolvePath(args[0]);
                    const pathParts = path.split('/').filter(p => p);
                    const dirName = pathParts.pop();
                    const parentPath = '/' + pathParts.join('/');
                    
                    const parent = getObjectAtPath(parentPath || '/');
                    if (parent && isDirectory(parent)) {
                        if (parent[dirName]) {
                            term.writeln(`\x1b[31mmkdir: ${args[0]}: File exists\x1b[0m`);
                        } else {
                            parent[dirName] = {};
                            term.writeln(`\x1b[32mDirectory '${args[0]}' created\x1b[0m`);
                        }
                    } else {
                        term.writeln(`\x1b[31mmkdir: cannot create directory '${args[0]}': No such file or directory\x1b[0m`);
                    }
                    return [];
                },
                
                'rmdir': () => {
                    if (args.length === 0) {
                        term.writeln('\x1b[31mUsage: rmdir <directory_name>\x1b[0m');
                        return [];
                    }
                    
                    const path = resolvePath(args[0]);
                    const pathParts = path.split('/').filter(p => p);
                    const dirName = pathParts.pop();
                    const parentPath = '/' + pathParts.join('/');
                    
                    const parent = getObjectAtPath(parentPath || '/');
                    if (parent && parent[dirName]) {
                        if (isDirectory(parent[dirName])) {
                            if (Object.keys(parent[dirName]).length === 0) {
                                delete parent[dirName];
                                term.writeln(`\x1b[32mDirectory '${args[0]}' removed\x1b[0m`);
                            } else {
                                term.writeln(`\x1b[31mrmdir: ${args[0]}: Directory not empty\x1b[0m`);
                            }
                        } else {
                            term.writeln(`\x1b[31mrmdir: ${args[0]}: Not a directory\x1b[0m`);
                        }
                    } else {
                        term.writeln(`\x1b[31mrmdir: ${args[0]}: No such directory\x1b[0m`);
                    }
                    return [];
                },
                
                'touch': () => {
                    if (args.length === 0) {
                        term.writeln('\x1b[31mUsage: touch <filename>\x1b[0m');
                        return [];
                    }
                    
                    const path = resolvePath(args[0]);
                    const pathParts = path.split('/').filter(p => p);
                    const fileName = pathParts.pop();
                    const dirPath = '/' + pathParts.join('/');
                    
                    const dir = getObjectAtPath(dirPath || currentPath);
                    if (dir && isDirectory(dir)) {
                        dir[fileName] = dir[fileName] || '';
                        term.writeln(`\x1b[32mFile '${args[0]}' created\x1b[0m`);
                    } else {
                        term.writeln(`\x1b[31mtouch: cannot touch '${args[0]}': No such file or directory\x1b[0m`);
                    }
                    return [];
                },
                
                'cat': () => {
                    if (pipeInput !== null) {
                        pipeInput.forEach(line => term.writeln(line));
                        return pipeInput;
                    }
                    
                    if (args.length === 0) {
                        term.writeln('\x1b[31mUsage: cat <filename>\x1b[0m');
                        return [];
                    }
                    
                    const path = resolvePath(args[0]);
                    const pathParts = path.split('/').filter(p => p);
                    const fileName = pathParts.pop();
                    const dirPath = '/' + pathParts.join('/');
                    
                    const dir = getObjectAtPath(dirPath || '/');
                    if (dir && dir[fileName] !== undefined) {
                        if (typeof dir[fileName] === 'string') {
                            const output = dir[fileName].split('\n');
                            output.forEach(line => term.writeln(line));
                            return output;
                        } else {
                            term.writeln(`\x1b[31mcat: ${args[0]}: Is a directory\x1b[0m`);
                        }
                    } else {
                        term.writeln(`\x1b[31mcat: ${args[0]}: No such file or directory\x1b[0m`);
                    }
                    return [];
                },
                
                'rm': () => {
                    if (args.length === 0) {
                        term.writeln('\x1b[31mUsage: rm [-r] <file_or_directory>\x1b[0m');
                        return [];
                    }
                    
                    const recursive = args[0] === '-r' || args[0] === '-rf';
                    const target = recursive ? args[1] : args[0];
                    
                    if (!target) {
                        term.writeln('\x1b[31mUsage: rm [-r] <file_or_directory>\x1b[0m');
                        return [];
                    }
                    
                    const path = resolvePath(target);
                    const pathParts = path.split('/').filter(p => p);
                    const name = pathParts.pop();
                    const parentPath = '/' + pathParts.join('/');
                    
                    const parent = getObjectAtPath(parentPath || '/');
                    if (parent && parent[name] !== undefined) {
                        if (isDirectory(parent[name]) && !recursive) {
                            term.writeln(`\x1b[31mrm: ${target}: is a directory (use -r to remove)\x1b[0m`);
                        } else {
                            delete parent[name];
                            term.writeln(`\x1b[32m'${target}' removed\x1b[0m`);
                        }
                    } else {
                        term.writeln(`\x1b[31mrm: ${target}: No such file or directory\x1b[0m`);
                    }
                    return [];
                },
                
                'mv': () => {
                    if (args.length < 2) {
                        term.writeln('\x1b[31mUsage: mv <source> <destination>\x1b[0m');
                        return [];
                    }
                    
                    const srcPath = resolvePath(args[0]);
                    const dstPath = resolvePath(args[1]);
                    
                    const srcParts = srcPath.split('/').filter(p => p);
                    const srcName = srcParts.pop();
                    const srcParentPath = '/' + srcParts.join('/');
                    
                    const dstParts = dstPath.split('/').filter(p => p);
                    const dstName = dstParts.pop();
                    const dstParentPath = '/' + dstParts.join('/');
                    
                    const srcParent = getObjectAtPath(srcParentPath || '/');
                    const dstParent = getObjectAtPath(dstParentPath || '/');
                    
                    if (srcParent && srcParent[srcName] !== undefined && dstParent && isDirectory(dstParent)) {
                        dstParent[dstName] = srcParent[srcName];
                        delete srcParent[srcName];
                        term.writeln(`\x1b[32m'${args[0]}' moved to '${args[1]}'\x1b[0m`);
                    } else {
                        term.writeln(`\x1b[31mmv: cannot move '${args[0]}' to '${args[1]}'\x1b[0m`);
                    }
                    return [];
                },
                
                'cp': () => {
                    if (args.length < 2) {
                        term.writeln('\x1b[31mUsage: cp <source> <destination>\x1b[0m');
                        return [];
                    }
                    
                    const srcPath = resolvePath(args[0]);
                    const dstPath = resolvePath(args[1]);
                    
                    const srcParts = srcPath.split('/').filter(p => p);
                    const srcName = srcParts.pop();
                    const srcParentPath = '/' + srcParts.join('/');
                    
                    const dstParts = dstPath.split('/').filter(p => p);
                    const dstName = dstParts.pop();
                    const dstParentPath = '/' + dstParts.join('/');
                    
                    const srcParent = getObjectAtPath(srcParentPath || '/');
                    const dstParent = getObjectAtPath(dstParentPath || '/');
                    
                    if (srcParent && srcParent[srcName] !== undefined && dstParent && isDirectory(dstParent)) {
                        if (typeof srcParent[srcName] === 'string') {
                            dstParent[dstName] = srcParent[srcName];
                            term.writeln(`\x1b[32m'${args[0]}' copied to '${args[1]}'\x1b[0m`);
                        } else {
                            term.writeln(`\x1b[31mcp: ${args[0]}: Is a directory (directory copy not implemented)\x1b[0m`);
                        }
                    } else {
                        term.writeln(`\x1b[31mcp: cannot copy '${args[0]}' to '${args[1]}'\x1b[0m`);
                    }
                    return [];
                },
                
                'grep': () => {
                    if (args.length === 0) {
                        term.writeln('\x1b[31mUsage: grep <pattern> [file] or <command> | grep <pattern>\x1b[0m');
                        return [];
                    }
                    
                    const pattern = args[0];
                    let searchLines = [];
                    
                    if (pipeInput !== null) {
                        searchLines = pipeInput;
                    } else if (args[1]) {
                        const path = resolvePath(args[1]);
                        const pathParts = path.split('/').filter(p => p);
                        const fileName = pathParts.pop();
                        const dirPath = '/' + pathParts.join('/');
                        const dir = getObjectAtPath(dirPath || '/');
                        
                        if (dir && typeof dir[fileName] === 'string') {
                            searchLines = dir[fileName].split('\n');
                        }
                    }
                    
                    const output = searchLines.filter(line => 
                        line.toLowerCase().includes(pattern.toLowerCase())
                    );
                    
                    output.forEach(line => term.writeln(line));
                    return output;
                },
                
                'find': () => {
                    const searchName = args[0] || '';
                    const output = [];
                    
                    function searchDir(path, obj) {
                        if (!isDirectory(obj)) return;
                        
                        for (const [name, value] of Object.entries(obj)) {
                            const fullPath = path + (path === '/' ? '' : '/') + name;
                            
                            if (name.includes(searchName)) {
                                output.push(fullPath);
                                term.writeln(fullPath);
                            }
                            
                            if (isDirectory(value)) {
                                searchDir(fullPath, value);
                            }
                        }
                    }
                    
                    searchDir('/', fileSystem['/']);
                    return output;
                },
                
                'echo': () => {
                    const output = [args.join(' ')];
                    term.writeln(output[0]);
                    return output;
                },
                
                'vim': () => {
                    if (args.length === 0) {
                        term.writeln('\x1b[31mUsage: vim <filename>\x1b[0m');
                        return [];
                    }
                    
                    vimFilename = args[0];
                    const path = resolvePath(vimFilename);
                    const pathParts = path.split('/').filter(p => p);
                    const fileName = pathParts.pop();
                    const dirPath = '/' + pathParts.join('/');
                    const dir = getObjectAtPath(dirPath || currentPath);
                    
                    if (dir && dir[fileName] !== undefined) {
                        if (typeof dir[fileName] === 'string') {
                            vimBuffer = dir[fileName].split('\n');
                        } else {
                            term.writeln(`\x1b[31mvim: ${vimFilename}: Is a directory\x1b[0m`);
                            return [];
                        }
                    } else {
                        vimBuffer = [''];
                    }
                    
                    vimMode = true;
                    vimInsertMode = false;
                    vimCommandMode = false;
                    vimCommandLine = '';
                    vimCurrentLine = 0;
                    displayVim();
                    return [];
                }
            };
            
            if (commands[command]) {
                return commands[command]();
            } else {
                term.writeln(`\x1b[31m${command}: command not found\x1b[0m`);
                return [];
            }
        }
        
        function displayVim() {
            term.clear();
            
            vimBuffer.forEach((line, i) => {
                if (i === vimCurrentLine && !vimCommandMode) {
                    term.writeln(`\x1b[7m${line || ' '}\x1b[0m`);
                } else {
                    term.writeln(line);
                }
            });
            
            term.write('\r\n');
            const mode = vimInsertMode ? '-- INSERT --' : (vimCommandMode ? '' : '-- NORMAL --');
            const status = `\x1b[7m ${vimFilename} [${vimBuffer.length} lines] ${mode} \x1b[0m`;
            term.writeln(status);
            
            if (!vimInsertMode && !vimCommandMode) {
                term.writeln('\x1b[33m[i=insert, j/k=move, :w=save, :q=quit, :wq=save&quit]\x1b[0m');
            }
            
            if (vimCommandMode) {
                term.write(':' + vimCommandLine);
            }
        }
        
        function handleVimInput(key, domEvent) {
            if (vimCommandMode) {
                if (domEvent.key === 'Enter') {
                    term.write('\r\n');
                    
                    if (vimCommandLine === 'w' || vimCommandLine === 'wq') {
                        const path = resolvePath(vimFilename);
                        const pathParts = path.split('/').filter(p => p);
                        const fileName = pathParts.pop();
                        const dirPath = '/' + pathParts.join('/');
                        const dir = getObjectAtPath(dirPath || currentPath);
                        
                        if (dir) {
                            dir[fileName] = vimBuffer.join('\n');
                            term.writeln(`\x1b[32m"${vimFilename}" ${vimBuffer.length} lines written\x1b[0m`);
                        }
                    }
                    
                    if (vimCommandLine === 'q' || vimCommandLine === 'wq' || vimCommandLine === 'q!') {
                        vimMode = false;
                        setTimeout(() => {
                            term.clear();
                            writePrompt();
                        }, vimCommandLine === 'wq' ? 800 : 0);
                    } else {
                        setTimeout(() => displayVim(), 1000);
                    }
                    
                    vimCommandMode = false;
                    vimCommandLine = '';
                } else if (domEvent.key === 'Escape') {
                    vimCommandMode = false;
                    vimCommandLine = '';
                    displayVim();
                } else if (domEvent.key === 'Backspace') {
                    if (vimCommandLine.length > 0) {
                        vimCommandLine = vimCommandLine.slice(0, -1);
                        displayVim();
                    }
                } else if (key.length === 1) {
                    vimCommandLine += key;
                    displayVim();
                }
            } else if (!vimInsertMode) {
                if (key === 'i') {
                    vimInsertMode = true;
                    displayVim();
                } else if (key === 'j' && vimCurrentLine < vimBuffer.length - 1) {
                    vimCurrentLine++;
                    displayVim();
                } else if (key === 'k' && vimCurrentLine > 0) {
                    vimCurrentLine--;
                    displayVim();
                } else if (key === ':') {
                    vimCommandMode = true;
                    displayVim();
                }
            } else {
                if (domEvent.key === 'Escape') {
                    vimInsertMode = false;
                    displayVim();
                } else if (domEvent.key === 'Enter') {
                    vimBuffer.splice(vimCurrentLine + 1, 0, '');
                    vimCurrentLine++;
                    displayVim();
                } else if (domEvent.key === 'Backspace') {
                    if (vimBuffer[vimCurrentLine].length > 0) {
                        vimBuffer[vimCurrentLine] = vimBuffer[vimCurrentLine].slice(0, -1);
                    } else if (vimCurrentLine > 0) {
                        vimBuffer.splice(vimCurrentLine, 1);
                        vimCurrentLine--;
                    }
                    displayVim();
                } else if (key.length === 1) {
                    vimBuffer[vimCurrentLine] = (vimBuffer[vimCurrentLine] || '') + key;
                    displayVim();
                }
            }
        }
        
        term.onKey(function(e) {
            if (vimMode) {
                handleVimInput(e.key, e.domEvent);
                return;
            }
            
            const ev = e.domEvent;
            const printable = !ev.altKey && !ev.ctrlKey && !ev.metaKey;
            
            if (ev.key === 'Enter') {
                term.write('\r\n');
                
                if (currentLine.trim()) {
                    commandHistory.push(currentLine.trim());
                    historyIndex = commandHistory.length;
                    processCommand(currentLine.trim());
                }
                
                currentLine = '';
                if (!vimMode) {
                    writePrompt();
                }
            } else if (ev.key === 'Backspace') {
                if (currentLine.length > 0) {
                    currentLine = currentLine.slice(0, -1);
                    term.write('\b \b');
                }
            } else if (ev.key === 'ArrowUp') {
                if (historyIndex > 0) {
                    historyIndex--;
                    replaceCurrentLine(commandHistory[historyIndex]);
                }
            } else if (ev.key === 'ArrowDown') {
                if (historyIndex < commandHistory.length - 1) {
                    historyIndex++;
                    replaceCurrentLine(commandHistory[historyIndex]);
                } else {
                    historyIndex = commandHistory.length;
                    replaceCurrentLine('');
                }
            } else if (ev.key === 'Tab') {
                ev.preventDefault();
            } else if (printable) {
                currentLine += e.key;
                term.write(e.key);
            }
        });
        
        function replaceCurrentLine(newLine) {
            term.write('\r');
            writePrompt();
            term.write(' '.repeat(currentLine.length));
            term.write('\r');
            writePrompt();
            currentLine = newLine;
            term.write(currentLine);
        }
        
    }, 100);
})();
</script>
