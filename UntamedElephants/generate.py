from PIL import Image
import random


#generations yeahhh generate me bb

#there are a few
array = [["Blue", "Dark Blue", "Grey", "Light Dark Purple", "Light Red", "Light Yellow", "Orange"],
         
         ["Black Bone", "Black Double Hoop", "Black Single Hoop", "Gold Double Hoop", "Gold Single Hoop", "White Bone", "None"],
         
         ["Laser Eyes White", "Laser Eyes Yellow", "3D Glasses", "Corrupted Shades", "Circular Sunglasses", "Cyborg", "Exhausted", "Male Sunglasses",
          "Monocle", "Glasses With Crack", "Rude", "Sad", "Shades Flip Up Lense", "Stoned", "Tired", "VR", "Wide Open", "Zombie", "Pop-Out"],
         
         ["1800's Top Hat", "Bandana", "Untamed Hat", "Baseball Pink", "Basketball ETH", "Beanie",
          "Bucket", "Chef", "Cowboy", "Devil Horns", "Brown Long-Hair", "Blonde Long-Hair",
          "Fisherman", "Black-Halo", "Gold-Halo", "Neat-Hair", "Slick-Hair", "Mohawk", "Sailor", "White Bandana", "Workout Bandana", "Red Halo", "Bald"],

         ["Untamed Hoodie", "Black Robe", "Fancy Suit", "Turtleneck", "Untamed Tee", "Basketball Shirt",
          "Fisherman Suit", "Hawaian Shirt", "Lab Coat", "Untamed Logo Tee", "Black Tee", "Red Turtleneck",
          "Safari Guide", "Save The Elephants", "Space Suit", "Striped Shirt", "Tank Top",
          "Untamed Black Tee", "Untamed Yellow Hoodie", "White Robe Silver Lining", "White Robe Black Lining", "Black Turtleneck", "I Heart Elephants", "Jail the Poachers", "Purple Tye-Dye", "Black Suit", "Tye Dye"],

         ["Black", "Blue", "Brown", "Dark Brown", "Grey", "Cyan", "Pink", "Red", "Orange", "Tan", "White", "Zombie", "Skeleton", "Cyborg", "Psychedelic", "Ghost", "Silver", "Bronze"],

         ["Cigarette", "1800's Pipe", "None"],

         ["Black", "Cyborg", "Ghost", "Diamond", "Psychedelic", "White", "Sapphire"]]


#arrayPercents = [[14.28, 14.28, 14.28, 14.28, 14.28, 14.28, 14.28],
                 #[1.5, 6, 8, 6.5, 7, 1, 70],

                 #[0.75, 1, 4.75, 7, 7, 1.5, 8, 5, 6, 6.5, 6.5, 7, 6, 7, 6, 3, 5, 2, 4],

                 #[5, 5, 5, 3, 5, 6, 5, 4, 5, 2.25, 2.25, 3.5, 1.25, 1.5, 6, 6, 4, 4, 4, 4, 1, 17.25],

                 #[4.5, 1.75, 4.5, 4.5, 4, 3, 4, 3.5, 4.5, 4.5, 6.5, 4.5, 5, 4.5, 4, 4, 4, 4, 4, 1.25, 1.5, 3, 2, 4, 2, 3, 4],

                 #[5, 7, 7.5, 7.5, 18, 9.75, 7, 6, 4, 10, 5, 3.5, 1, 1.5, 2, 1.25, 2, 2],

                 #[10, 10, 80],
                 #[13, 2.5, 1.5, 4.5, 3.5, 73, 2]]

# HAH Light Red, White Bone, Laser Eyes White, Red Halo, White Robe Black Lining, Cyborg, 1800's Pipe, Ghost

arrayLimits = [[1071, 1072, 1071, 1072, 1071, 1072, 1071],
               [112, 450, 600, 487, 525, 75, 5251],
               
               [63, 75, 356, 600, 600, 112, 600, 450, 450, 562, 565, 525, 450, 525, 495, 225, 375, 172, 300],
               
               [375, 375, 375, 225, 375, 450, 300, 375, 300, 112, 168, 168, 262, 93, 112, 450, 450, 300, 375, 262, 300, 75, 1223],
               

               [337, 131, 337, 337, 300, 225, 300, 262, 337, 337, 493, 337, 375, 337, 300, 300, 300, 300, 300, 93, 112, 225, 150, 300, 150, 225, 300],

               
               [375, 525, 562, 562, 1353, 731, 525, 450, 300, 750, 375, 262, 75, 112, 150, 93, 150, 150],
               [750, 750, 6000],
               [975, 187, 112, 337, 262, 5477, 150]]

arrayCounter = [[2, 0, 0, 0, 1, 1, 0],
               [0, 0, 0, 0, 1, 1, 2],
               
               [0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0],
               
               [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0],
               

               [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],

               
               [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0],
               [0, 0, 4],
               [0, 0, 1, 1, 0, 2, 0]]

arrayOfGenerations = []

top0 = len(array[0])-1
bottom0 = 0
top1 = len(array[1])-1
bottom1 = 0
top2 = len(array[2])-1
bottom2 = 0
top3 = len(array[3])-1
bottom3 = 0
top4 = len(array[4])-1
bottom4 = 0
top5 = len(array[5])-1
bottom5 = 0
top6 = len(array[6])-1
bottom6 = 0
top7 = len(array[7])-1
bottom7 = 0

print("Loading generations, this should take up to 2 mins, if the Elephants are not being generated by then in a folder, it means the software is stuck in a loop...")




def randomNum(numb):
    possible = False
    endReturn = 0
    if (numb == 0):
        while (possible == False):
            endReturn = random.randint(bottom0, top0)
            if (arrayCounter[0][endReturn] <= arrayLimits[0][endReturn]):
                possible = True
        return endReturn
    elif (numb == 1):
        while (possible == False):
            endReturn = random.randint(bottom1, top1)
            if (arrayCounter[1][endReturn] <= arrayLimits[1][endReturn]):
                possible = True
        return endReturn
    elif (numb == 2):
        while (possible == False):
            endReturn = random.randint(bottom2, top2)
            if (arrayCounter[2][endReturn] <= arrayLimits[2][endReturn]):
                possible = True
        return endReturn
    elif (numb == 3):
        while (possible == False):
            endReturn = random.randint(bottom3, top3)
            if (arrayCounter[3][endReturn] <= arrayLimits[3][endReturn]):
                possible = True
        return endReturn
    elif (numb == 4):
        while (possible == False):
            endReturn = random.randint(bottom4, top4)
            if (arrayCounter[4][endReturn] <= arrayLimits[4][endReturn]):
                possible = True
        return endReturn
    elif (numb == 5):
        while (possible == False):
            endReturn = random.randint(bottom5, top5)
            if (arrayCounter[5][endReturn] <= arrayLimits[5][endReturn]):
                possible = True
        return endReturn
    elif (numb == 6):
        while (possible == False):
            endReturn = random.randint(bottom6, top6)
            if (arrayCounter[6][endReturn] <= arrayLimits[6][endReturn]):
                possible = True
        return endReturn
    elif (numb == 7):
        while (possible == False):
            endReturn = random.randint(bottom7, top7)
            if (arrayCounter[7][endReturn] <= arrayLimits[7][endReturn]):
                possible = True
        return endReturn

            
for dasdasd in range(355):
    x = dasdasd + 7145
    var = False
    while (var == False):
        currentArray = []
        
        currentArray.append(randomNum(0))
        currentArray.append(randomNum(1))
        currentArray.append(randomNum(2))
        currentArray.append(randomNum(3))
        currentArray.append(randomNum(4))
        currentArray.append(randomNum(5))
        currentArray.append(randomNum(6))
        currentArray.append(randomNum(7))


        var2 = False
        if (currentArray[5] == 12):
            if (currentArray[1] != len(array[1])-1):
                #print('Skeleton and earrings so not gonna work!')
                currentArray[1] = len(array[1])-1
            if (currentArray[7] != len(array[7])-1):
                #print('Skeleton and non-white tusk so not gonna work!')
                currentArray[1] = len(array[1])-1
            if (currentArray[4] == 5 or currentArray[4] == 6 or currentArray[4] == 10 or currentArray[4] == 13 or currentArray[4] == 16 or currentArray[4] == 7):
                #print('Skeleton and shirt wont fit or wont look good!')
                var2 = True

        
        if (currentArray in arrayOfGenerations):
            var2 = True

        if (arrayCounter[0][currentArray[0]] <= arrayLimits[0][currentArray[0]]):
            if (arrayCounter[0][currentArray[0]] == bottom0):
                if (arrayCounter[0][currentArray[0]] == arrayLimits[0][currentArray[0]]):
                    if (bottom0 < top0):
                        bottom0 = bottom0 + 1

            if (arrayCounter[0][currentArray[0]] == top0):
                if (arrayCounter[0][currentArray[0]] == arrayLimits[0][currentArray[0]]):
                    if (bottom0 < top0):
                        top0 = top0 - 1
            
            if (arrayCounter[1][currentArray[1]] <= arrayLimits[1][currentArray[1]]):
                if (arrayCounter[1][currentArray[1]] == bottom1):
                    if (arrayCounter[1][currentArray[1]] == arrayLimits[1][currentArray[1]]):
                        if (bottom1 < top1):
                            bottom1 = bottom1 + 1

                if (arrayCounter[1][currentArray[1]] == top1):
                    if (arrayCounter[1][currentArray[1]] == arrayLimits[1][currentArray[1]]):
                        if (bottom1 < top1):
                            top1 = top1 - 1
                        
                if (arrayCounter[2][currentArray[2]] <= arrayLimits[2][currentArray[2]]):
                    if (arrayCounter[2][currentArray[2]] == bottom2):
                        if (arrayCounter[2][currentArray[2]] == arrayLimits[2][currentArray[2]]):
                            if (bottom2 < top2):
                                bottom2 = bottom2 + 1

                    if (arrayCounter[2][currentArray[2]] == top2):
                        if (arrayCounter[2][currentArray[2]] == arrayLimits[2][currentArray[2]]):
                            if (bottom2 < top2):
                                top2 = top2 - 1

                    
                    if (arrayCounter[3][currentArray[3]] <= arrayLimits[3][currentArray[3]]):
                        if (arrayCounter[3][currentArray[3]] == bottom3):
                            if (arrayCounter[3][currentArray[3]] == arrayLimits[3][currentArray[3]]):
                                if (bottom3 < top3):
                                    bottom3 = bottom3 + 1

                        if (arrayCounter[3][currentArray[3]] == top3):
                            if (arrayCounter[3][currentArray[3]] == arrayLimits[3][currentArray[3]]):
                                if (bottom3 < top3):
                                    top3 = top3 - 1
                        
                        if (arrayCounter[4][currentArray[4]] <= arrayLimits[4][currentArray[4]]):
                            if (arrayCounter[4][currentArray[4]] == bottom4):
                                if (arrayCounter[4][currentArray[4]] == arrayLimits[4][currentArray[4]]):
                                    if (bottom4 < top4):
                                        bottom4 = bottom4 + 1

                            if (arrayCounter[4][currentArray[4]] == top4):
                                if (arrayCounter[4][currentArray[4]] == arrayLimits[4][currentArray[4]]):
                                    if (bottom4 < top4):
                                        top4 = top4 - 1
                            
                            if (arrayCounter[5][currentArray[5]] <= arrayLimits[5][currentArray[5]]):
                                if (arrayCounter[5][currentArray[5]] == bottom5):
                                    if (arrayCounter[5][currentArray[5]] == arrayLimits[5][currentArray[5]]):
                                        if (bottom5 < top5):
                                            bottom5 = bottom5 + 1

                                if (arrayCounter[5][currentArray[5]] == top5):
                                    if (arrayCounter[5][currentArray[5]] == arrayLimits[5][currentArray[5]]):
                                        if (bottom5 < top5):
                                            top5 = top5 - 1

                                
                                if (arrayCounter[6][currentArray[6]] <= arrayLimits[6][currentArray[6]]):
                                    if (arrayCounter[6][currentArray[6]] == bottom6):
                                        if (arrayCounter[6][currentArray[6]] == arrayLimits[6][currentArray[6]]):
                                            if (bottom6 < top6):
                                                bottom6 = bottom6 + 1

                                    if (arrayCounter[6][currentArray[6]] == top6):
                                        if (arrayCounter[6][currentArray[6]] == arrayLimits[6][currentArray[6]]):
                                            if (bottom6 < top6):
                                                top6 = top6 - 1
                                    
                                    if (arrayCounter[7][currentArray[7]] <= arrayLimits[7][currentArray[7]]):
                                        if (arrayCounter[7][currentArray[7]] == bottom7):
                                            if (arrayCounter[7][currentArray[7]] == arrayLimits[7][currentArray[7]]):
                                                if (bottom7 < top7):
                                                    bottom7 = bottom7 + 1

                                        if (arrayCounter[7][currentArray[7]] == top7):
                                            if (arrayCounter[7][currentArray[7]] == arrayLimits[7][currentArray[7]]):
                                                if (bottom7 < top7):
                                                    top7 = top7 - 1
                                        
                                        if (var2 == False):
                                            #print([bottom0, top0, bottom1, top1, bottom2, top2, bottom3, top3, bottom4, top4, bottom5, top5, bottom6, top6, bottom7, top7])
                                            print(len(arrayOfGenerations))
                                            arrayCounter[0][currentArray[0]] = arrayCounter[0][currentArray[0]] + 1
                                            arrayCounter[1][currentArray[1]] = arrayCounter[1][currentArray[1]] + 1
                                            arrayCounter[2][currentArray[2]] = arrayCounter[2][currentArray[2]] + 1
                                            arrayCounter[3][currentArray[3]] = arrayCounter[3][currentArray[3]] + 1
                                            arrayCounter[4][currentArray[4]] = arrayCounter[4][currentArray[4]] + 1
                                            arrayCounter[5][currentArray[5]] = arrayCounter[5][currentArray[5]] + 1
                                            arrayCounter[6][currentArray[6]] = arrayCounter[6][currentArray[6]] + 1
                                            arrayCounter[7][currentArray[7]] = arrayCounter[7][currentArray[7]] + 1
                                            arrayOfGenerations.append(currentArray)
                                            var = True


#print(arrayOfGenerations)
#print(len(array[0]) + len(array[1]) + len(array[2]) + len(array[3]) + len(array[4]) + len(array[5]) + len(array[6]) + len(array[7]))
print("============================================================================================")
print("Layering Elephants and pre metadata...")
for fsdfsdf in range(len(arrayOfGenerations)):
    index = fsdfsdf
    back = Image.open("back/" + str(arrayOfGenerations[index][0]) + ".jpg")
    skin = Image.open("skin/" + str(arrayOfGenerations[index][5]) + ".png")
    
    if (arrayOfGenerations[index][3] != len(array[3])-1):
        head = Image.open("head/" + str(arrayOfGenerations[index][3]) + ".png")
    eyes = Image.open("eyes/" + str(arrayOfGenerations[index][2]) + ".png")
    if (arrayOfGenerations[index][1] != len(array[1])-1):
        earrings = Image.open("earrings/" + str(arrayOfGenerations[index][1]) + ".png")
    shirt = Image.open("shirts/" + str(arrayOfGenerations[index][4]) + ".png")
    tusks = Image.open("tusk/" + str(arrayOfGenerations[index][7]) + ".png")
    if (arrayOfGenerations[index][6] != len(array[6])-1):
        mouth = Image.open("mouth/" + str(arrayOfGenerations[index][6]) + ".png")

    back.paste(skin, (0, 0), skin)
    back.paste(shirt, (0, 0), shirt)
    if ((arrayOfGenerations[index][2] == 0 or arrayOfGenerations[index][2] == 1 or arrayOfGenerations[index][2] == 5 or arrayOfGenerations[index][2] == 6 or arrayOfGenerations[index][2] == 7 or arrayOfGenerations[index][2] == 9 or
        arrayOfGenerations[index][2] == 11 or arrayOfGenerations[index][2] == 12 or arrayOfGenerations[index][2] == 14 or arrayOfGenerations[index][2] == 15 or arrayOfGenerations[index][2] == 17 or arrayOfGenerations[index][2] == 18 or
        arrayOfGenerations[index][2] == 19 or arrayOfGenerations[index][2] == 10 or arrayOfGenerations[index][2] == 2 or arrayOfGenerations[index][2] == 8 or arrayOfGenerations[index][2] == 3 or arrayOfGenerations[index][2] == 4) and
        (arrayOfGenerations[index][3] != 15 or arrayOfGenerations[index][3] != 16) or # Checking for eyes and glasses that go below hats or above hats
        (arrayOfGenerations[index][2] == 16 and (arrayOfGenerations[index][3] == 0 or arrayOfGenerations[index][3] == 2 or
          arrayOfGenerations[index][3] == 3 or arrayOfGenerations[index][3] == 4 or arrayOfGenerations[index][3] == 6 or
         arrayOfGenerations[index][3] == 8 or arrayOfGenerations[index][3] == 12 or arrayOfGenerations[index][3] == 18 or arrayOfGenerations[index][3] == 5))):  # VR


        
        back.paste(eyes, (0, 0), eyes)
        if (arrayOfGenerations[index][3] != len(array[3])-1):
            back.paste(head, (0, 0), head)
    else:
        if (arrayOfGenerations[index][3] != len(array[3])-1):
            back.paste(head, (0, 0), head)
        back.paste(eyes, (0, 0), eyes)
    
    if (arrayOfGenerations[index][1] != len(array[1])-1):
        back.paste(earrings, (0, 0), earrings)
    
    back.paste(tusks, (0, 0), tusks)
    if (arrayOfGenerations[index][6] != len(array[6])-1):
        back.paste(mouth, (0, 0), mouth)


    back.save("Elephants/" + str(index+7145) + ".png", "PNG")

    f = open("Metadata/" + str(index+7145), "w")

    meta = '{"attributes":[{"trait_type":"Head","value":"' + array[3][arrayOfGenerations[index][3]] + '"},'
    meta = meta + '{"trait_type":"Torso","value":"' + array[4][arrayOfGenerations[index][4]] + '"},{"trait_type":"Eyes","value":"' + array[2][arrayOfGenerations[index][2]] + '"},'
    meta = meta + '{"trait_type":"Mouth","value":"' + array[6][arrayOfGenerations[index][6]] + '"},{"trait_type":"Earring","value":"' + array[1][arrayOfGenerations[index][1]] + '"},'
    meta = meta + '{"trait_type":"Tusks","value":"' + array[7][arrayOfGenerations[index][7]] + '"},{"trait_type":"Skin","value":"' + array[5][arrayOfGenerations[index][5]] + '"},'
    meta = meta + '{"trait_type":"Background","value":"' + array[0][arrayOfGenerations[index][0]] + '"}],"description":"7,500 Untamed Elephants Roaming Around On The Ethereum Blockchain Waiting To Be Saved. Official Store At [www.untamedelephants.io](https://www.untamedelephants.io/).",'
    
    f.write(meta +
            '"image":"https://untamedelephants.io/metaHidden/hidden.gif",' +
            '"name":"Untamed Elephant #' + str(index+7145) + '"}')
    f.close()

    print(str(index) + ".png and " + str(index+7145) + " json generated!")




print("============================================================================================")
print("Listing Elephants traits used")
for each in range(len(arrayCounter)):
    for anotherEach in range(len(array[each])):
        print(str(arrayCounter[each][anotherEach]) + " out of " + str(arrayLimits[each][anotherEach]) + " " + array[each][anotherEach])

















