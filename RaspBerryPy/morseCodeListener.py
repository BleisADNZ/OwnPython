import RPi.GPIO as GPIO
import time

GPIO.setmode(GPIO.BOARD)

GPIO.setup(11, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)

GPIO.setup(7, GPIO.OUT)
GPIO.output(7, 0)
millisOn = 0
millisOff = 0
millis = 0
userInput = []
userChars = []
userOutput = ""
temporalString = ""
morse = {{"A", ".-"},{"B", "-..."},{"C", "-.-."},{"D", "-.."},{"E", "."},
         {"F", "..-."},{"G", "--."},{"H", "...."},{"I", ".."},{"J", ".---"},
         {"K", "-.-"},{"L", ".-.."},{"M", "--"},{"N", "-."},{"O", "---"},
         {"P", ".--."},{"Q", "--.-"},{"R", ".-."},{"S", "..."},{"T", "-"},
         {"U", "..-"},{"V", "...-"},{"W", ".--"},{"X", "-..-"},{"Y", "-..-"},
         {"Z", "--.."},{"0", "-----"},{"1", ".----"},{"2", "..---"},{"3", "...--"},
         {"4", "....-"},{"5", "....."},{"6", "-...."},{"7", "--..."},{"8", "---.."},
         {"9", "----."}}

try:
    while True:
        if (GPIO.input(11) = 1):
            GPIO.output(7, 1)
            if (millisOn == 0):
                millisOn = int(round(time.time() * 1000))
        else:
            GPIO.output(7, 0)
            millisOff = int(round(time.time() * 1000))
            if (millisOn > 0):
                millis = millisOff - millisOn
                if (millis < 150):
                    print "."
                    userInput.append('.')
                elif (millis > 150 && millis < 500):
                    print "-"
                    userInput.append('-')
                elif (millis > 1000 && millis < 5000):
                    print "Next Character"
                    userInput.append(' ')
                elif (millis > 5000):
                    print "End of Message"
                    userInput.append(' ')
                    for char in userInput:
                        if (char == '.' || char == '-'):
                            temporalString += char
                        elif (char == ' '):
                            for value in morse:
                                if (value[1] == temporalString):
                                    userOutput += value[0]
                                    print value[0]
                            temporalString = ""
                    print userOutput
                time.sleep(1)
                millisOn = 0
except KeyboardInterrupt:
    GPIO.cleanup()
