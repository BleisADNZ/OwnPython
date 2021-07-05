from PIL import Image

back = Image.open("back/5.jpg")
skin = Image.open("skin/14.png")
head = Image.open("head/14.png")
eyes = Image.open("eyes/10.png")
earrings = Image.open("earrings/4.png")
shirt = Image.open("shirts/15.png")
tusks = Image.open("tusk/5.png")
#mouth = Image.open("mouth/" + str(arrayOfGenerations[index][6]) + ".png")


#Mingo - 0, 15, 18, 2, none, 15, 5
#Devin - 0, 13, 13, 16, 5, 8, 4, 5
#tESTING - 4, 7, 9, 4, none, 11, 0
#gzork - 5, 14, 14, 10, 4, 15, 5, 

back.paste(skin, (0, 0), skin)
back.paste(shirt, (0, 0), shirt)
back.paste(eyes, (0, 0), eyes)
back.paste(head, (0, 0), head)
back.paste(earrings, (0, 0), earrings)
back.paste(tusks, (0, 0), tusks)
#back.paste(mouth, (0, 0), mouth)
back.save("zero4.png", "PNG")
