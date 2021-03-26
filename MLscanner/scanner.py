import tkinter
import tkinter.font as ft
from tkinter.filedialog import askopenfilename
import tkinter.messagebox
from PIL import Image, ImageTk
from classify import predict


mainWin = tkinter.Tk()
mainWin.title('ML-based Malware Scanner')
mainWin.geometry('380x500')
mainWin.resizable(0, 0)
mainWin['bg'] = '#8d8d8c'

logo = Image.open('static/logo.png').resize((150, 150))
render = ImageTk.PhotoImage(logo)
img = tkinter.Label(mainWin, image=render, bd=0)
img.image = render
img.place(x=115, y=110)

titleFont = ft.Font(family='Helvetica', size=18, weight=ft.BOLD, slant=ft.ROMAN)
labelTitle = tkinter.Label(mainWin, text='ML-based Malware Scanner', fg='#ffffff', bg='#8d8d8c', font=titleFont)
labelTitle.place(x=33, y=70)

textFont = ft.Font(family='Helvetica', size=12, weight=ft.BOLD, slant=ft.ROMAN)
inputFont = ft.Font(family='Calibri', size=10, weight=ft.NORMAL, slant=ft.ROMAN)
labelPath = tkinter.Label(mainWin, text='EXE file path →', font=textFont, fg='#ffffff', bg='#8d8d8c')
labelPath.place(x=85, y=290)
path = tkinter.StringVar()
entryPath = tkinter.Entry(mainWin, width=80, textvariable=path, font=inputFont, bg='#1c1c1c')
entryPath.place(x=25, y=340, width=330, height=40)

def selectPath():
	path.set(askopenfilename(initialdir='../test'))

selectButtonFont = ft.Font(family='Helvetica', size=12, weight=ft.BOLD, slant=ft.ROMAN)
selectButton = tkinter.Button(mainWin, text='Open File', command=selectPath, bg='#4876ff', fg='white', font=selectButtonFont, bd=3, activebackground='#27408b')
selectButton.place(x=215, y=280, width=90, height=40)

def check(*args):
	file_path = path.get()
	result = predict('model/classifier.pkl', 'model/features.pkl', file_path)
	if result:
		tkinter.messagebox.showinfo('INFO', message='No threat found')
	else:
		tkinter.messagebox.showwarning('WARNING', message='Malware detected!')
		

mainWin.bind('<Return>', check)
textFont = ft.Font(family='Helvetica', size=14, weight=ft.BOLD, slant=ft.ROMAN)
checkButton = tkinter.Button(mainWin, text='Check', command=check, bg='#d82d2d', fg='white', font=textFont, bd=3, activebackground='#8b1a1a')
checkButton.place(x=130, y=410, width=120, height=50)

mainWin.mainloop()

