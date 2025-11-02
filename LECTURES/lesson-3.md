###### LESSON 3: INTERNET PROTOCOLS ######

How does the Internet work?

The internet works by sending packets of information across the network.
There are certain technologies that determine how this information is sent and with what.
These are called *protocols*

What's a protocol?

A protocol is basically just a regulation or ruleset for 
how certain data is sent. The two we'll talk about are TCP and UDP.
TCP, or Transmission Control Protocol, basically sends packets in a way
where it's about QUALITY over speed. This means that packets are sent in full
functionality, which means that data is reliable and uncorrupted. However,
UDP, or User Datagram Protocol, is more about speed and efficiency.

TCP is then used in other protocols, like FTP for file transfers, 
HTTP or HTTPS, which is for displaying web pages, SMTP for emails, etc.

UDP is used for things like video game chats,
video conferencing like Zoom calls, and VoIP, or Voice over Internet Protocol,
which basically means voice chats. This speed but lack of accuracy
is what can lead to freezing or stuttering or missing data.

When data is sent using TCP, there's this thing called a TCP header,
which contains important information that helps routers *route* where
the packet should go, hopping to the right location, and eventually going back.


Data reliability vs validity?

Data is reliable when it's uncorrupted and functional.
But data can be reliable and also invalid. Valid data means
accurate data. For example, if I have a text file that contains
people's heights and the file is uncorrupted, it's reliable.
But if the heights I write down are in seconds, and not in feet or cm,
then most likely the data is invalid.


What about Networks?

In terms of networks, when we connect different computers together,
that is an INTERnet. An INTRAnet would be a local network, but an INTERnet
would be (usually) across longer distances, and at a large scale. But technically
the local network of your home could be called an internet, but that's not what we usually say.

There's different network models out there, such as LAN or WLAN, PAN, 
and there's various security solutions to keep these things safe.
A LAN is basically just a local area network of computers. A WLAN is just
just a Wide LAN. So a corporate building or a college campus network would be a WLAN (technically there are
more specific terminologies for these, but it's fine). A PAN is a Personal Area Network.
When you connect peripherals (like a mouse or keyboard) wirelessly, or use your wireless
earbuds to listen to music, that is an example of a PAN. A 1-person network with more than one device, interconnected.

Security?

VPNS, firewalls, and other intrusion prevension systems are used to protect these networks.
This is the core of cybersecurity. Keeping our networks safe from attackers. But don't think
that these solutions keep you completely anonymous or anything. There's a lot of information out there.
We can go more in depth on these later in a future lesson about online anonymity and security.

When are we getting to the cool stuff? 

If you're talking about commands in the terminal...Don't worry.
In the next lesson, we're jumping straight into the basics
of Kali Linux.
