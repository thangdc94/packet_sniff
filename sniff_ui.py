from tkinter import *
from packetsniff import PacketSniff
import time
import _thread

# Here, we are creating our class, Window, and inheriting from the Frame
# class. Frame is a class from the tkinter module. (see Lib/tkinter/__init__)


class Window(Frame):

    # Define settings upon initialization. Here you can specify
    def __init__(self, master=None):

        # parameters that you want to send through the Frame class.
        Frame.__init__(self, master)

        # reference to the master widget, which is the tk window
        self.master = master
        self.ps = None

        # with that, we want to then run init_window, which doesn't yet exist
        self.init_window()

    # Creation of init_window
    def init_window(self):

        # changing the title of our master widget
        self.master.title("GUI")

        # allowing the widget to take the full space of the root window
        self.pack(fill=BOTH, expand=1)

        # creating a button instance
        startButton = Button(self, text="Start",
                             command=self.start_btn_handler)
        stopButton = Button(self, text="Stop", command=self.stop_btn_handler)

        text = Text(self, height=30, width=100)
        self.ps = PacketSniff(text)

        # placing the button on my window
        startButton.place(x=0, y=0)
        stopButton.place(x=100, y=0)
        text.place(x=0, y=50)

    def start_btn_handler(self):
        _thread.start_new_thread(self.thread_handler, ())

    def stop_btn_handler(self):
        self.ps.stop()

    # Define a function for the thread
    def thread_handler(self):
        self.ps.start()


# root window created. Here, that would be the only window, but
# you can later have windows within windows.
root = Tk()

root.geometry("700x500")

# creation of an instance
app = Window(root)

# mainloop
root.mainloop()
