# Intro to Linux & Commands

What is Linux? What are commands? How do I do said commands?
Fear not, that's what this lesson is all about!

To begin, let's define a seemingly unrelated term: Operating Systems. An operating system is the software
that supports the functions of your computer, like executing apps, controlling peripherals like a mouse or keyboard,
and scheduling tasks like updates.

Examples of this would be Windows 11/10, Linux, MacOS, BSD, Android, ChromeOS, UNIX, etc.

We are focusing in on Linux, as Linux gives us the most freedom whilst also being relatively easier to learn
that alternatives. By freedom, we mean that with Linux, we can get down to that kernel level access mentioned previously.
But what **flavor** of Linux shall we use? For those who aren't familiar, there are different distributions, or **distros** of Linux.
They're basically different versions of Linux that look and operate differently, but are fundamentally the same overall. The one we'll be using
moving forwards is **Kali Linux**, which is specially designed for penetration testing (future topic) and is Debian-based (means it comes from the Debian version of Linux).


# Commands

So...what exactly is a command? Well, if your parents tell you what to do, like chores, that's a command. Similarly, when we type 
commands into a **terminal emulator**, we command the computer to follow through with a sort of chore. But what's a terminal emulator?
A terminal emulator is a big scary text box where we type commands in. That's it.

```bash
ls -> lists files in current directory
cat <file> -> spits out whats in the file in plain text
mv <source> <destination> -> moves a file to a destination directory
touch <file> -> makes the file
grep <pattern> <file> -> searches for that pattern in the file. Like if a word appears in it
man <command> -> linux manual for this command. How to do this command?
help -> Gives you the list of available commands and other useful info
sudo <command> -> Gives you super user do permissions. Do this as the admin. 
cp <source> <destination> -> copy a file to a destination directory
cd <directory> -> change to this directory
ls -a -> list ALL files, even the hidden ones
rm <file> -> removes a file
mkdir <directory> -> makes a new directory inside the current working one
rm -rf <directory> -> removes all files recursively in a directory (so the directory and everything in it, including subdirectories)
rmdir <directory> -> same thing as above command, but a different way of doing it
cd -> if you just type "cd" it brings you to the home, or ~ directory. This is your starting point
```

We'll be practicing these commands using a **Virtual Machine**, which is a pretend computer that uses a Virtual Disk.
We do this so that we don't have to install on *bare metal*, which is just your actual computer. Assuming you have your schoolwork,
games, and messaging apps and other important files on your main computer, we don't want to erase that. So, we use a Virtual Machine.
Unless you want to dual-boot, which is a more advanced technique involving installing multiple operating systems on one computer, but that's
a more advanced topic.


For practice with commands, you can either run them in a VM, or do so here: [Terminal Practice](../../test.md)


If you want to learn how to install Kali Linux, follow the installation process here: [Linux Installation Process](../../LECTURES/unit1/installation-process/)
