import random
import string
from datetime import datetime

def popChar(msg, index):
    newMsg = msg[:index] + msg[index+1:]
    return newMsg

def addCharOnLoc(msg, char, index):
    newMsg = msg[:index] + char + msg[index:]
    return newMsg
    

def firstAl(msg):
    random.seed(int(input("Seed => "))) #Get seed
    x = len(msg) #Set the length of the message

    while (x > 0): #Go through "x" loops
        number = random.randint(0, len(msg)-1) #Choose a random number from 0 to the length of the message
        newChar = msg[number] #Use the random number as a index to select a character in the message
        msg = popChar(msg, number) #Use popChar() to take the character out

        msg = msg + newChar #Add the previously saved character on the message withoput the character
        x = x - 1 #Just using this variable for the loop

    return msg

def firstAlD(msg):
    random.seed(int(input("Seed => "))) #Get seed
    x = len(msg) #Set the length of the message
    numbers = []
    
    for y in range(x): #Use "x" to go through the loop
        numbers.append(random.randint(0, len(msg)-1)) #To store the random numbers used in the process of encrypting

    while (x > 0): #Creating a loop to decrypt the code
        newChar = msg[len(msg)-1] #Store the last char of "msg"
        msg = popChar(msg, len(msg)-1) #Remove the character from msg
        msg = addCharOnLoc(msg, newChar, numbers[x-1]) #Use the random numbers to place them where the were
        x = x - 1 #Variable used for the while loop
        
    return msg

def createKeys(p1, p2):     # =======================================    Key Creation = Process may take 5-10 minutes
    
    n = p1 * p2                                                     #First, following the steps, create the first public key by using two high prime numbers
    phyN = (p1-1) * (p2-1)                                          #We get the phy funtion out of them
    
    print("Mr. Key:", n)                                            #Displaying key
    print(datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],  #And date and time for reference
          "Creating Keys...")                                       #as the process may take a few minutes depending on the size of the keys
    
    nCoprimes = coprimes(n)                                         #Find coprime numbers of both the key and the phy funtion of it
    phyNCoprimes = coprimes(phyN)                                   #
##    print(datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],  #Display date time again
##          nCoprimes)
##    print(datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],  #For reference
##          phyNCoprimes)
    encryptionKeys = []                                             #Creating new array to get the encryption key
    
    x = len(phyNCoprimes)-1                                         #Create two variabels with the length of "phyNCoprimes" and "nCoprimes"
    y = len(nCoprimes)-1                                            #
    while (x > 0):                                                  #Go through "phyNCoprimes"

        
##        while (y > 0):                                              #Then inside it go through "nCoprimes"
##            if (phyNCoprimes[x] == nCoprimes[y]):                   #Then check if any number in "nCoprimes" is equals to the current "phyNCoprimes" 
##                encryptionKeys.append(x)                            #Store the encryption public key
##                break                                               #break the loop to stop the loop after getting the key
##        if (len(encryptionKeys) == 1):                              #Check on the outer loop if the encryption key has been obtained
##            break                                                   #if true the loop will break to stop
                                                                    # ==== If the breaks are not in place the loops will lead to a "MemoryError"

        if (phyNCoprimes[x] in nCoprimes):                          #Check if the phyNCoprime number is in nCoprimes ^^^Less iterations
            encryptionKeys.append(x)                                #If true then store the key
            break                                                   #and break
                                                                    # ==== The break here is just to stop once the key is obtained

##    for key in phyNCoprimes:
##        print(key)
##        if (key in nCoprimes):
##            encryptionKeys.append(key)
##            break


    print(datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3], "Keys Created!")     #An alert on the key being created will appear with the date and time
    e = encryptionKeys[len(encryptionKeys)-1]                                           #Set a variable for the encryption public key
    decryptionKeys = deModPhyNEqualsOne(e, phyN, n)                                     #Run the decryption key finder method
    d = decryptionKeys[len(decryptionKeys)-1]                                           #Store the key to display it
    print("Public Key:", e)                                                             #Display encryption public key
    print("Private Key:", d)#decryptionKeys)                                            #Display decryption private key
    #Fun fact, the ^^ stated above as ecryption key and decryption key can be interchanged,
    #like, the decryption key can be used as the encryption key and vice-versa
    #The idea is that nobody can work out the decryption key while the Mr. Key and the encryption key are public

    
def encryptRSA (msg, ekey, key): #=================== Encryption
    message = ""
    for characterIndex in range(len(msg)):
        message = message + str(ndModPhyKey(ord(msg[characterIndex]), ekey, key)) + ":"
    return message

def decryptRSA (msg, dkey, key): #=================== Decryption
    message = ""
    tempCharacter = ""
    for characterIndex in range(len(msg)):
        if (isANumber(msg[characterIndex])):
            tempCharacter = tempCharacter + msg[characterIndex]
        else:
            #print(int(tempCharacter))
            message = message + chr(ndModPhyKey(int(tempCharacter), dkey, key))
            tempCharacter = ""

    return message

def isANumber (n): #Variable checker
    try:
        int(n)
        return True
    except(ValueError):
        return False
    

def ndModPhyKey(n , d, key):                #Following ( n ** d ( mod ( phy(key) ) ) ) ===================== Method used for encryption and decryption
    result = 0                              #A result variable is initilized to store the result of the equation
    result = n**d                           #Following the equation, this line starts by multiplying  (n * d)

    
##    while (result >= 0):                    #The result is set on "result", now, "result" is used
##        result = result - key               #by substracting key every time and stoping when "result" goes negative
##    result = result + key                   #Then just make sure to go one step back to turn it positive

    result = result % key                   #This method, to find modulus "key" less iteration than ^^
    
    return result                           #Output the result



def deModPhyNEqualsOne(eNumber , phyNumber, number):    #Following ( decrypt * encrypt ( mod ( phy(number) ) ) ) == 1 ============ This is just to find the decrypt key
    tempNumber = 0                                      #Temporal number is created
    #result = 0
    results = []                                        #An array  is created
    key = number-1
    while (key > 0):                                    #This method goes through every possible decryption key
        tempNumber = key*eNumber                        #Following the equation, this line starts by multiplying  (decrypt * encrypt)

        
##        while (tempNumber >= 0): #The result is set on "tempNumber", now, "tempNumber" is used
##            tempNumber = tempNumber - phyNumber #by substracting phyNumber every time and stoping when "tempNumber" goes under 0
##        if ((tempNumber+phyNumber) == 1): #Then by grabing the negative number left we add "phyNumber"

        
        if ((tempNumber%phyNumber) == 1):               # (tempNumber % phyNumber) is (n ( mod ( phy(number) )), in python % is used to find the modulus, this method takes less time than the code above^^^^^ 
            results.append(key)                         #this will be the (mod (phy(number)) )  of the equation, then we check the result to see if its 1, then save it in "results"
            break
        key = key - 1

    return results                                      #Output the array


def checkCommonFactors(number):         #Getting common factors for "number" ============ Warning, the use of this function requires too many iterations for larger numbers
    factors = []                        #Create array to store the common factors
    x = 2                               #Start checking from 2
    while (x <= number):                #Go through every number from "x" to number
        y = format(number / x, '.2f')   #divide "number" by "x" and store it in "y"
        if (y.is_integer()):            #Check if "y" is an integer
            factors.append(x)           #If it is it means that it is a factor and so it appends to "factors"
        x = x + 1                       #Increase "x" by one

    return factors #Return it

def checkCommonFactorsOut(n): #Same thing as the funtion above ^^^^^^
    nonFactors = []
    x = 2
    while (x <= n):
        y = format(n / x, '.2f')
        if (y.is_integer() == False): #However it gives you non-factors
            #print("y: ", y)
            nonFactors.append(x)
        x = x + 1

    return nonFactors

def coprimes (number):
    coprimes = [] #Array for cprime numbers is created
##    numberFactors = checkCommonFactors(number) #An array is created to store the common factors of the main number
##    temporalNumberFactors = [] #An array is created to be used in the loop as a number from 1 to the main number
##    hasSameFactor = False
    x = number - 1                                      #Start of the loop is set
    while (x > 0):                                      #Loop goes through every number till the main number
        
##        temporalNumberFactors = checkCommonFactors(x)   #The common factors for the selected number are set
##        hasSameFactor = False                           #I set a condition to check whether "x" common factors is not sharing "number" common factors
##        for y in temporalNumberFactors:                 #Go through "x" common factors
##            for i in numberFactors:                     #Then through "number" common factors
##                if (y == i):                            #Then in this loop check if any of the "number" common factors aka "i" match the current "x" common factor aka "y"
##                    hasSameFactor = True;               #If true then "hasSameFactor" is set to True
##        if (hasSameFactor == False):                    #Here we add the coprime numbers, if they dont share any factors
##            coprimes.append(x)                          #We append the checked number ("x") to "coprimes"


        if (areCoprimeWith(x, number)):                 #Using new method to check for coprimes as the code above^^^ requires too many iterations
            coprimes.append(x)                          #So if "x" and "number" are coprimes then "x" is added to "coprimes"
            
        x = x - 1                                       #Gradual increase by 1

    return coprimes #Return the coprime numbers

def areCoprimeWith (a , b): #Algorithm to find greatest common factor between two numbers andif it is 1 they are coprime http://mathworld.wolfram.com/EuclideanAlgorithm.html
    result = 0 #The end result for this loop
    x = a
    y = b
    while (x != 0 and y != 0):      #First, while x and y are not 0
        if (x > y):                 #We check which of x and y is higer so we take (modulus(lowest number)) out of the higher number
            x = x % y               #Then by checking the modulus following the same pattern
        else:                       #One of them will end up being 0 but the other will have to be the greatest common divisor
            y = y % x

    if (x > y):                     #Now, if the gretest common divisor between two numbers is 1 it means that they share no factors
        result = x                  #Meaning they are Coprime
    else:
        result = y

    #print(result)
    if (result == 1):               #If not the function will just return False
        return True
        
    return False
    

def is_prime(n): 
    if n <= 1: 
        return False
    for i in range(2,n): 
        if n % i == 0: 
            return False
    return True


def primeNumbers (lowest, highest):                 #Method to find prime numbers
    for num in range(lowest,highest + 1):           #Make a loop go from a number to another
        if num > 1:                                 #Withou counting 1
            if (is_prime(num)): #Check the amount of common factors, if the amount counts to 1 its a prime number
                print(num, "\n\nyeaaaaah")                          #Display the prime number





p1 = 131059#17#1627  131059
p2 = 131063#19#1979  131063


n = p1 * p2
phyN = (p1-1)*(p2-1)



#print(deModPhyNEqualsOne(95, phyN, n))
#print(createKeys(p1, p2))
#print(n)
#print(coprimes(323))
#print(primeNumbers(minimum_key_size, maximum_key_size-2))
#print(encryptRSA("H", 5, 14))#ndModPhyKey(2, 5, 14))#deModPhyNequalsOne(5, 6, 14))#step1(2, 7))#coprimes(14), coprimes(6))#checkCommonFactors(14), checkCommonFactors(6))#step1(2, 7))#firstAlD(input("Message => ")))
#print(primeNumbers(100000, 101000))
#print(areCoprimeWith(116150, 232704))

#17
#19
##Mr. Key: 323
##2019-04-18 00:14:45.147 Creating Keys...
##2019-04-18 00:14:45.158 Keys Created!
##Public Key: 95 
##Private Key: 191
#print(ndModPhyKey(20, 95, 323))
#print(ndModPhyKey(210, 191, 323))


#print(ndModPhyKey(72, 997919, 3219833))
#print(ndModPhyKey(2279252, 2595191, 3219833))
# 109987
# 100853

#100703
#100927

#1877
#1907

#=========================================================== Tests
#       1627
#       1979
##      ----

## First process ======= SUCCESS!
##Mr. Key: 3219833
##2019-04-15 22:33:46.319 Creating Keys...
##2019-04-15 22:38:37.142 Keys Created!
##Public Key: [997919]
##Private Key: [2595191]


## second Process ======== FAIL! Whole encryption key finder array was upside down
##Mr. Key: 3219833
##2019-04-15 22:48:08.893 Creating Keys...
##2019-04-15 22:52:58.925 Keys Created!
##Public Key: [1]
##Private Key: [1, 3216229]


## third process ========= FAIL! The public and Private key are the same
##Mr. Key: 3219833
##2019-04-16 00:29:59.194 Creating Keys...
##2019-04-16 00:30:24.701 Keys Created!
##Public Key: [3216227]
##Private Key: [3216227]


##Final Process ========= SUCCESS! The new coprime() method and the old createKey() make everything work
##Mr. Key: 3219833
##2019-04-16 04:30:43.793 Creating Keys...
##2019-04-16 04:31:09.244 Keys Created!
##Public Key: [997919]
##Private Key: [2595191]
##=======Inside story, coprime() method stores the coprime number from high to low,
##=======however the createKey() method to find the public key goes from low to high to find the key
##=======seems that the key has to be a lower shared number between both coprime arrays



##Encryption Tests ========== SUCCESS!
##Using p1 = 1627 p2 = 1979
##Mr. Key: 3219833
##Public Key: [997919]
##Private Key: [2595191]
##print(encryptRSA("Hello World!", 997919, 3219833))
##print(decryptRSA("2279252:3187618:2581300:2581300:2191994:1160533:2614391:2191994:2479540:2581300:2540308:312246:", 2595191, 3219833))
