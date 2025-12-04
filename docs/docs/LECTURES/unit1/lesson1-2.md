# Rings of Access

Let's jump right into it! **Protection rings** are a hardware-level security feature on the **CPU (Central Processing Unit)**.
When you think of CPU, think of that sticker you see on your laptop or PC that says Intel or AMD.
That chip is a CPU, and it's in charge of managing important instructions on the computer. 

These "rings" determine the level of access from the **operating system** kernel (in this case the OS is **Linux**, which we'll talk about next lesson)
to the user application. The most priviledged rings, where the most damage can be done the the most caution must be exercised, are the inner rings.
The amount of priviledge provided grows as you approach the inner rings. The user typically resides in the outer most ring to do most of their applications.
But with what we're going to be doing, we're going far deeper than the surface. The intermediate rings are for drivers to communicate between what the user does
and what the kernel needs to do. What a kernel is is essentially just what controls the hardware itself at the lower level.

Drivers are special software that translate a hardware device's instructions for the computer. For example, mouse movements, printers printing a document,
graphics cards displaying something on screen, headphones or speakers, etc.

The diagram below illustrates this:

<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/2/2f/Priv_rings.svg/1200px-Priv_rings.svg.png" />

Source: [Rings of Access Diagram](https://en.wikipedia.org/wiki/Protection_ring)


But why this model? We use this to make sure when we run a command, we know how potentially impactful it could be. It prevents
us from doing something not knowing it could destroy our system, and allows us to understand more intricately how the computer
really is working. I know this doesn't sound like "security" yet, but we need to build our foundations first.
