// Auto-generated search index - DO NOT EDIT
window.searchIndex = {
  "config": {
    "lang": [
      "en"
    ],
    "separator": "[\\s\\-]+"
  },
  "docs": [
    {
      "location": "/unit1",
      "title": "Overview",
      "text": "UNIT 1: Introduction to Linux and the Field of Cybersecurity Welcome to Cybersecurity! This was the unit we covered in our early meetings, but essentially this unit covers the basics of what Cybersecurity is all about, and a little intro to how to setup linux for the future, so in later lessons we can start applying what we learn on our machines! :) To begin, let's move on to Lesson 1.1 ← Previous: Home Current Lesson Overview Next: Lesson 1.1 →"
    },
    {
      "location": "/unit3",
      "title": "Unit 3",
      "text": "← Previous: Unit 2 Current Lesson Unit 3 Next: Terminal →"
    },
    {
      "location": "/unit2",
      "title": "Unit 2",
      "text": "← Previous: Linux Installation Process Current Lesson Unit 2 Next: Unit 3 →"
    },
    {
      "location": "/test",
      "title": "Terminal",
      "text": "Terminal Here's an interactive terminal with full Linux commands: ← Previous: Unit 3 Current Lesson Terminal Next →"
    },
    {
      "location": "/LECTURES/unit1/lesson1-2",
      "title": "Lesson 1.2",
      "text": "Rings of Access Let's jump right into it! Protection rings are a hardware-level security feature on the CPU (Central Processing Unit) . When you think of CPU, think of that sticker you see on your laptop or PC that says Intel or AMD. That chip is a CPU, and it's in charge of managing important instructions on the computer. These \"rings\" determine the level of access from the operating system kernel (in this case the OS is Linux , which we'll talk about next lesson) to the user application. The most priviledged rings, where the most damage can be done the the most caution must be exercised, are the inner rings. The amount of priviledge provided grows as you approach the inner rings. The user typically resides in the outer most ring to do most of their applications. But with what we're going to be doing, we're going far deeper than the surface. The intermediate rings are for drivers to communicate between what the user does and what the kernel needs to do. What a kernel is is essentially just what controls the hardware itself at the lower level. Drivers are special software that translate a hardware device's instructions for the computer. For example, mouse movements, printers printing a document, graphics cards displaying something on screen, headphones or speakers, etc. The diagram below illustrates this: Source: Rings of Access Diagram But why this model? We use this to make sure when we run a command, we know how potentially impactful it could be. It prevents us from doing something not knowing it could destroy our system, and allows us to understand more intricately how the computer really is working. I know this doesn't sound like \"security\" yet, but we need to build our foundations first. ← Previous: Lesson 1.1 Current Lesson Lesson 1.2 Next: Lesson 1.3 →"
    },
    {
      "location": "/LECTURES/unit1/installation-process",
      "title": "Linux Installation Process",
      "text": "What is it? Kali is an operating system that was made specially for cybersecurity work (and hacking as well). It has a large toolkit of useful programs that we're going to learn about, including Hydra, Nmap, Wireshark, Tcpdump, MacChanger, Chisel, Aircrack-ng, etc. Some Vocab: As much as we know vocabulary might not be that interesting, it's important to know for the future, since there's a LOT of acronyms and words in cybersecurity that you're going to be hearing and using, so it's best to get used to it. Operating System (OS) : The main software that runs your computer, like Windows, macOS, iOS, GNU/Linux, etc. Virtual Machine (VM) : It's basically a computer inside another computer. You can run your regular OS, like Windows, and still have Kali Linux inside of it ISO File (International Organization for Standardization File) : Sounds fancy, but really it's just a full copy of an OS within one tiny file Hypervisor : Software that creates and manages VMs. Examples are VirtualBox and VMWare Workstation. There's also QEMU, but mostly Linux users use that, and you're likely running on Windows or mac Bootable USB : Just a USB drive (which you hopefully already know about) that can start up a computer and install an OS (we don't need this yet) Partitioning : A more advanced topic, but it's dividing up your drive into sections called partitions , which are like walls for a room. We don't need this yet, but it is good to know Now, let's get into the nitty-gritty: Method 1: Easy way :) Minimum Requirements*: 8 GB of RAM 20-30 GB of free hard drive space A decently fast CPU (you probably have this) *But, how do I know if I meet them? Well, you can press Ctrl+Shift+Esc on Windows and click on \"Performance\" inside of Task Manager, and it'll give you a spec (specifications) sheet. On mac, you can click on \"About\" in the top menu bar of your computer. On Linux, you can type uname -a , or use a custom program like fastfetch BIG DISCLAIMER FOR WINDOWS USERS: You NEED to DISABLE s"
    },
    {
      "location": "/LECTURES/unit1/lesson1-3",
      "title": "Lesson 1.3",
      "text": "Intro to Linux &amp; Commands What is Linux? What are commands? How do I do said commands? Fear not, that's what this lesson is all about! To begin, let's define a seemingly unrelated term: Operating Systems. An operating system is the software that supports the functions of your computer, like executing apps, controlling peripherals like a mouse or keyboard, and scheduling tasks like updates. Examples of this would be Windows 11/10, Linux, MacOS, BSD, Android, ChromeOS, UNIX, etc. We are focusing in on Linux, as Linux gives us the most freedom whilst also being relatively easier to learn that alternatives. By freedom, we mean that with Linux, we can get down to that kernel level access mentioned previously. But what flavor of Linux shall we use? For those who aren't familiar, there are different distributions, or distros of Linux. They're basically different versions of Linux that look and operate differently, but are fundamentally the same overall. The one we'll be using moving forwards is Kali Linux , which is specially designed for penetration testing (future topic) and is Debian-based (means it comes from the Debian version of Linux). Commands So...what exactly is a command? Well, if your parents tell you what to do, like chores, that's a command. Similarly, when we type commands into a terminal emulator , we command the computer to follow through with a sort of chore. But what's a terminal emulator? A terminal emulator is a big scary text box where we type commands in. That's it. ls -&gt; lists files in current directory cat &lt;file&gt; -&gt; spits out whats in the file in plain text mv &lt;source&gt; &lt;destination&gt; -&gt; moves a file to a destination directory touch &lt;file&gt; -&gt; makes the file grep &lt;pattern&gt; &lt;file&gt; -&gt; searches for that pattern in the file. Like if a word appears in it man &lt;command&gt; -&gt; linux manual for this command. How to do this command? help -&gt; Gives you the list of available commands and other useful "
    },
    {
      "location": "/LECTURES/unit1/lesson1-1",
      "title": "Lesson 1.1",
      "text": "What do we know about Cybersecurity? Cybersecurity sounds like what it is exactly . Cyber, meaning digital, and security, meaning safety and protection. So digital protection/prevention/safety. But what does that really mean? Well you could say that cybersecurity is about how we can protect computers, servers, systems, etc. from digital attacks. These attacks oculd be viruses, worms, ransomware, etc. In order to keep sensitive data safe, we need to protect against the exploitation of security vulnerabilities. These are some cybersecurity goals: Identify and fix security vulnerabilities Prevent unauthorized access and data breaches Protect systems from malicious attacks Ensure integrity and availability of information Source: GeeksforGeeks ← Previous: Overview Current Lesson Lesson 1.1 Next: Lesson 1.2 →"
    },
    {
      "location": "/LECTURES/unit2/lesson2-1",
      "title": "Lesson2 1",
      "text": "LESSON 3: INTERNET PROTOCOLS How does the Internet work? The internet works by sending packets of information across the network. There are certain technologies that determine how this information is sent and with what. These are called protocols What's a protocol? A protocol is basically just a regulation or ruleset for how certain data is sent. The two we'll talk about are TCP and UDP. TCP, or Transmission Control Protocol, basically sends packets in a way where it's about QUALITY over speed. This means that packets are sent in full functionality, which means that data is reliable and uncorrupted. However, UDP, or User Datagram Protocol, is more about speed and efficiency. TCP is then used in other protocols, like FTP for file transfers, HTTP or HTTPS, which is for displaying web pages, SMTP for emails, etc. UDP is used for things like video game chats, video conferencing like Zoom calls, and VoIP, or Voice over Internet Protocol, which basically means voice chats. This speed but lack of accuracy is what can lead to freezing or stuttering or missing data. When data is sent using TCP, there's this thing called a TCP header, which contains important information that helps routers route where the packet should go, hopping to the right location, and eventually going back. Data reliability vs validity? Data is reliable when it's uncorrupted and functional. But data can be reliable and also invalid. Valid data means accurate data. For example, if I have a text file that contains people's heights and the file is uncorrupted, it's reliable. But if the heights I write down are in seconds, and not in feet or cm, then most likely the data is invalid. What about Networks? In terms of networks, when we connect different computers together, that is an INTERnet. An INTRAnet would be a local network, but an INTERnet would be (usually) across longer distances, and at a large scale. But technically the local network of your home could be called an internet, but that's not what we u"
    }
  ]
};
console.log('✓ Search index loaded:', window.searchIndex.docs.length, 'documents');
