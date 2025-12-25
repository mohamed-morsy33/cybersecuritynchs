(function() {
    'use strict';
    
    // Check if xterm is loaded
    function initTerminal() {
        if (typeof Terminal === 'undefined') {
            console.error('Xterm.js not loaded. Make sure xterm script is loaded before terminal-init.js');
            return;
        }

        const container = document.querySelector('.terminal-content');
        
        // Only initialize if the container exists on the page
        if (!container) {
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
        
        // Simple file system simulation
        let fileSystem = {
            '/': {
                'home': {
                    'user': {
                        'documents': {},
                        'projects': {
                            'readme.txt': 'Welcome to the project!'
                        }
                    }
                },
                'etc': {},
                'var': {}
            }
        };
        
        let currentPath = '/home/user';
        let currentLine = '';
        let commandHistory = [];
        let historyIndex = -1;
        
        // Vim mode state
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
        
        // Handle keyboard input
        term.onKey(({ key, domEvent }) => {
            // If in vim mode, handle vim keybindings
            if (vimMode) {
                handleVimInput(key, domEvent);
                return;
            }
            
            const printable = !domEvent.altKey && !domEvent.ctrlKey && !domEvent.metaKey;
            
            if (domEvent.key === 'Enter') {
                term.write('\r\n');
                
                const command = currentLine.trim();
                if (command) {
                    commandHistory.push(command);
                    historyIndex = commandHistory.length;
                    processCommand(command);
                } else {
                    writePrompt();
                }
                
                currentLine = '';
            } else if (domEvent.key === 'Backspace') {
                if (currentLine.length > 0) {
                    currentLine = currentLine.slice(0, -1);
                    term.write('\b \b');
                }
            } else if (domEvent.key === 'ArrowUp') {
                // Navigate command history up
                if (historyIndex > 0) {
                    historyIndex--;
                    replaceCurrentLine(commandHistory[historyIndex]);
                }
            } else if (domEvent.key === 'ArrowDown') {
                // Navigate command history down
                if (historyIndex < commandHistory.length - 1) {
                    historyIndex++;
                    replaceCurrentLine(commandHistory[historyIndex]);
                } else {
                    historyIndex = commandHistory.length;
                    replaceCurrentLine('');
                }
            } else if (domEvent.key === 'Tab') {
                domEvent.preventDefault();
                // Could implement tab completion here
            } else if (printable) {
                currentLine += key;
                term.write(key);
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
        
        // Get object at path
        function getObjectAtPath(path) {
            const parts = path.split('/').filter(p => p);
            let current = fileSystem['/'];
            
            for (const part of parts) {
                if (current[part] === undefined) {
                    return null;
                }
                current = current[part];
            }
            return current;
        }
        
        // Process commands
        function processCommand(cmd) {
            const parts = cmd.split(' ').filter(p => p);
            const command = parts[0];
            const args = parts.slice(1);
            
            const commands = {
                'help': () => {
                    term.writeln('\x1b[1;33mAvailable Commands:\x1b[0m');
                    term.writeln('  \x1b[36mhelp\x1b[0m       - Show this help message');
                    term.writeln('  \x1b[36mclear\x1b[0m      - Clear the terminal screen');
                    term.writeln('  \x1b[36mecho\x1b[0m       - Print text to terminal');
                    term.writeln('  \x1b[36mdate\x1b[0m       - Show current date and time');
                    term.writeln('  \x1b[36mpwd\x1b[0m        - Print working directory');
                    term.writeln('  \x1b[36mls\x1b[0m         - List directory contents');
                    term.writeln('  \x1b[36mcd\x1b[0m         - Change directory');
                    term.writeln('  \x1b[36mmkdir\x1b[0m      - Create a new directory');
                    term.writeln('  \x1b[36mtouch\x1b[0m      - Create a new file');
                    term.writeln('  \x1b[36mcat\x1b[0m        - Display file contents');
                    term.writeln('  \x1b[36mrm\x1b[0m         - Remove file or directory');
                    term.writeln('  \x1b[36mwhoami\x1b[0m     - Display current user');
                    term.writeln('  \x1b[36muname\x1b[0m      - Display system information');
                    term.writeln('  \x1b[36mvim\x1b[0m        - Text editor (experimental)');
                },
                
                'clear': () => {
                    term.clear();
                },
                
                'date': () => {
                    term.writeln(new Date().toString());
                },
                
                'pwd': () => {
                    term.writeln(currentPath);
                },
                
                'whoami': () => {
                    term.writeln('user');
                },
                
                'uname': () => {
                    if (args[0] === '-a') {
                        term.writeln('Linux mkdocs 5.15.0 #1 SMP x86_64 GNU/Linux');
                    } else {
                        term.writeln('Linux');
                    }
                },
                
                'ls': () => {
                    const obj = getObjectAtPath(currentPath);
                    if (!obj) {
                        term.writeln('\x1b[31mError: Invalid path\x1b[0m');
                        return;
                    }
                    
                    const entries = Object.keys(obj);
                    if (entries.length === 0) {
                        term.writeln('(empty directory)');
                        return;
                    }
                    
                    entries.forEach(entry => {
                        if (typeof obj[entry] === 'object' && obj[entry] !== null) {
                            term.writeln(`\x1b[1;34m${entry}/\x1b[0m`);
                        } else {
                            term.writeln(`\x1b[37m${entry}\x1b[0m`);
                        }
                    });
                },
                
                'cd': () => {
                    if (args.length === 0 || args[0] === '~') {
                        currentPath = '/home/user';
                        return;
                    }
                    
                    let newPath;
                    if (args[0].startsWith('/')) {
                        newPath = args[0];
                    } else if (args[0] === '..') {
                        const parts = currentPath.split('/').filter(p => p);
                        parts.pop();
                        newPath = '/' + parts.join('/');
                        if (newPath === '/') newPath = '/';
                    } else {
                        newPath = currentPath + (currentPath.endsWith('/') ? '' : '/') + args[0];
                    }
                    
                    const obj = getObjectAtPath(newPath);
                    if (obj && typeof obj === 'object') {
                        currentPath = newPath;
                    } else {
                        term.writeln(`\x1b[31mcd: ${args[0]}: No such directory\x1b[0m`);
                    }
                },
                
                'mkdir': () => {
                    if (args.length === 0) {
                        term.writeln('\x1b[31mUsage: mkdir <directory_name>\x1b[0m');
                        return;
                    }
                    
                    const obj = getObjectAtPath(currentPath);
                    if (obj && typeof obj === 'object') {
                        if (obj[args[0]]) {
                            term.writeln(`\x1b[31mmkdir: ${args[0]}: File or directory already exists\x1b[0m`);
                        } else {
                            obj[args[0]] = {};
                            term.writeln(`\x1b[32mDirectory '${args[0]}' created\x1b[0m`);
                        }
                    }
                },
                
                'touch': () => {
                    if (args.length === 0) {
                        term.writeln('\x1b[31mUsage: touch <filename>\x1b[0m');
                        return;
                    }
                    
                    const obj = getObjectAtPath(currentPath);
                    if (obj && typeof obj === 'object') {
                        obj[args[0]] = '';
                        term.writeln(`\x1b[32mFile '${args[0]}' created\x1b[0m`);
                    }
                },
                
                'cat': () => {
                    if (args.length === 0) {
                        term.writeln('\x1b[31mUsage: cat <filename>\x1b[0m');
                        return;
                    }
                    
                    const obj = getObjectAtPath(currentPath);
                    if (obj && obj[args[0]] !== undefined) {
                        if (typeof obj[args[0]] === 'string') {
                            term.writeln(obj[args[0]] || '(empty file)');
                        } else {
                            term.writeln(`\x1b[31mcat: ${args[0]}: Is a directory\x1b[0m`);
                        }
                    } else {
                        term.writeln(`\x1b[31mcat: ${args[0]}: No such file\x1b[0m`);
                    }
                },
                
                'rm': () => {
                    if (args.length === 0) {
                        term.writeln('\x1b[31mUsage: rm <filename>\x1b[0m');
                        return;
                    }
                    
                    const obj = getObjectAtPath(currentPath);
                    if (obj && obj[args[0]] !== undefined) {
                        delete obj[args[0]];
                        term.writeln(`\x1b[32m'${args[0]}' removed\x1b[0m`);
                    } else {
                        term.writeln(`\x1b[31mrm: ${args[0]}: No such file or directory\x1b[0m`);
                    }
                },
                
                'echo': () => {
                    term.writeln(args.join(' '));
                },
                
                'vim': () => {
                    if (args.length === 0) {
                        term.writeln('\x1b[31mUsage: vim <filename>\x1b[0m');
                        return;
                    }
                    
                    vimFilename = args[0];
                    const obj = getObjectAtPath(currentPath);
                    
                    // Load file content or create new
                    if (obj && obj[vimFilename] !== undefined) {
                        if (typeof obj[vimFilename] === 'string') {
                            vimBuffer = obj[vimFilename].split('\n');
                        } else {
                            term.writeln(`\x1b[31mvim: ${vimFilename}: Is a directory\x1b[0m`);
                            return;
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
                }
            };
            
            if (commands[command]) {
                commands[command]();
            } else {
                term.writeln(`\x1b[31m${command}: command not found\x1b[0m`);
            }
            
            writePrompt();
        }
        
        // Vim functionality
        function displayVim() {
            term.clear();
            
            // Display file content
            vimBuffer.forEach((line, i) => {
                if (i === vimCurrentLine && !vimCommandMode) {
                    term.writeln(`\x1b[7m${line || ' '}\x1b[0m`);
                } else {
                    term.writeln(line);
                }
            });
            
            // Status line
            term.write('\r\n');
            const mode = vimInsertMode ? '-- INSERT --' : (vimCommandMode ? '' : '-- NORMAL --');
            const status = `\x1b[7m ${vimFilename} [${vimBuffer.length} lines] ${mode} \x1b[0m`;
            term.writeln(status);
            
            if (!vimInsertMode && !vimCommandMode) {
                term.writeln('\x1b[33m[i=insert, j/k=move, :w=save, :q=quit, :wq=save&quit, :q!=quit without save]\x1b[0m');
            } else if (vimInsertMode) {
                term.writeln('\x1b[33m[ESC=normal mode, type to insert text]\x1b[0m');
            }
            
            if (vimCommandMode) {
                term.write(':' + vimCommandLine);
            }
        }
        
        function handleVimInput(key, domEvent) {
            if (vimCommandMode) {
                if (domEvent.key === 'Enter') {
                    term.write('\r\n');
                    executeVimCommand(vimCommandLine.trim());
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
                } else if (key.length === 1 && !domEvent.ctrlKey && !domEvent.altKey && !domEvent.metaKey) {
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
                } else if (key.length === 1 && !domEvent.ctrlKey && !domEvent.altKey && !domEvent.metaKey) {
                    vimBuffer[vimCurrentLine] = (vimBuffer[vimCurrentLine] || '') + key;
                    displayVim();
                }
            }
        }
        
        function executeVimCommand(cmd) {
            if (cmd === 'w') {
                const obj = getObjectAtPath(currentPath);
                if (obj) {
                    obj[vimFilename] = vimBuffer.join('\n');
                    term.writeln(`\x1b[32m"${vimFilename}" ${vimBuffer.length} lines written\x1b[0m`);
                }
                setTimeout(() => displayVim(), 1000);
            } else if (cmd === 'q') {
                vimMode = false;
                term.clear();
                writePrompt();
            } else if (cmd === 'wq') {
                const obj = getObjectAtPath(currentPath);
                if (obj) {
                    obj[vimFilename] = vimBuffer.join('\n');
                    term.writeln(`\x1b[32m"${vimFilename}" ${vimBuffer.length} lines written\x1b[0m`);
                }
                vimMode = false;
                setTimeout(() => {
                    term.clear();
                    writePrompt();
                }, 800);
            } else if (cmd === 'q!') {
                vimMode = false;
                term.clear();
                writePrompt();
            } else if (cmd) {
                term.writeln(`\x1b[31mNot an editor command: ${cmd}\x1b[0m`);
                setTimeout(() => displayVim(), 1000);
            } else {
                displayVim();
            }
        }
    }
    
    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initTerminal);
    } else {
        // DOM already loaded
        initTerminal();
    }
})();
