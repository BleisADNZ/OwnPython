import pygame, sys, time, math
from pygame.locals import *

# Set up pygame.
pygame.init()

# Set up the window.
WINDOWWIDTH = 1000
WINDOWHEIGHT = 1000
windowSurface = pygame.display.set_mode((WINDOWWIDTH, WINDOWHEIGHT),
      0, 32)
pygame.display.set_caption('Animation')

# Set up direction variables.
DOWNLEFT = 'downleft'
DOWNRIGHT = 'downright'
UPLEFT = 'upleft'
UPRIGHT = 'upright'
UP = 'up'
DOWN = 'down'
LEFT = 'left'
RIGHT = 'right'

MOVESPEED = 5

# Set up the colors.
WHITE = (255, 255, 255)
RED = (255, 0, 0)
GREEN = (0, 255, 0)
BLUE = (0, 0, 255)
# Set up the box data structure.
b1 = {'rect':pygame.Rect(300, 80, 50, 100), 'color':RED, 'dir':UPRIGHT}
b2 = {'rect':pygame.Rect(200, 200, 20, 20), 'color':GREEN, 'dir':UPLEFT}
b3 = {'rect':pygame.Rect(100, 150, 60, 60), 'color':BLUE, 'dir':DOWNLEFT}
boxes = [b1, b2, b3]
user = []
##user = (BLUE, (int(WINDOWWIDTH/2), int(WINDOWHEIGHT/2)), WINDOWWIDTH/30, WINDOWWIDTH/40)
user.append(BLUE)
location = []
location.append(int(WINDOWWIDTH/2))
location.append(int(WINDOWHEIGHT/2))
user.append(location)
user.append(WINDOWWIDTH/50)
user.append(WINDOWWIDTH/60)
user.append(BLUE)
userPointerSpacer = WINDOWWIDTH/70
location = []
location.append(int(WINDOWWIDTH/2))
location.append(int(WINDOWHEIGHT/2)-WINDOWWIDTH/70)
user.append(location)
user.append(WINDOWWIDTH/70)
user.append(WINDOWWIDTH/80)

# Run the game loop.


def givedirection(position, userpositon):
    distance = []
    distance.append(position[0] - userpositon[0])
    distance.append(position[1] - userpositon[1])
    norm = math.sqrt(distance[0] ** 2 + distance[1] ** 2)
    direction = [distance[0] / norm, distance[1] / norm]
    print(direction)
    directionString = UP
    if direction[0] < -0.25 and direction[0] > -0.75 and direction[1] > -0.75 and direction[1] < -0.25:
        directionString = UPLEFT
    elif direction[0] > 0.25 and direction[0] < 0.75 and direction[1] > -0.75 and direction[1] < -0.25:
        directionString = UPRIGHT
    elif direction[0] < -0.25 and direction[0] > -0.75 and direction[1] > 0.25 and direction[1] < 0.75:
        directionString = DOWNLEFT
    elif direction[0] > 0.25 and direction[0] < 0.75 and direction[1] < 0.75 and direction[1] > 0.25:
        directionString = DOWNRIGHT
    elif direction[0] > -0.25 and direction[0] < 0.25 and direction[1] < -0.75:
        directionString = UP
    elif direction[0] > -0.25 and direction[0] < 0.25 and direction[1] > 0.75:
        directionString = DOWN
    elif direction[0] < -0.75 and direction[1] > -0.25 and direction[1] < 0.25:
        directionString = LEFT
    elif direction[0] > 0.75 and direction[1] > -0.25 and direction[1] < 0.25:
        directionString = RIGHT

    if direction[0] < 0.0:
        # Left Side
        if direction[1] < 0.0:
            directionString = UPLEFT
        else:
            directionString = DOWNLEFT
    else:
        # Right Side
        if direction[1] < 0.0:
            directionString = UPRIGHT
        else:
            directionString = DOWNRIGHT
##    if position[0] < userpositon[0]:
##        # Left Side
##        if position[1] < userpositon[1]:
##            directionString = UPLEFT
##        else:
##            directionString = DOWNLEFT
##    else:
##        # Right Side
##        if position[1] < userpositon[1]:
##            directionString = UPRIGHT
##        else:
##            directionString = DOWNRIGHT
    print("Direction " + directionString )
    return directionString

aim = UP
location = []
location.append(int(user[1][0]))
location.append(int(user[1][1]))
while True:
# Check for the QUIT event.
    for event in pygame.event.get():
        if event.type == QUIT:
            pygame.quit()
            sys.exit()
        if event.type == pygame.KEYDOWN:
            if event.key == pygame.K_a:
                user[1][0] = int(user[1][0] - WINDOWWIDTH/40)
            if event.key == pygame.K_d:
                user[1][0] = int(user[1][0] + WINDOWWIDTH/40)
            if event.key == pygame.K_w:
                user[1][1] = int(user[1][1] - WINDOWHEIGHT/40)
            if event.key == pygame.K_s:
                user[1][1] = int(user[1][1] + WINDOWHEIGHT/40)

        
        if event.type == pygame.MOUSEBUTTONDOWN:
            # prints on the console the pressed button and its position at that moment
            #print(u'button {} pressed in the position {}'.format(event.button, event.pos))
            if event.button == 1:
                aim = givedirection(event.pos, (int(user[1][0]), int(user[1][1])))
        location[0] = int(user[1][0])
        location[1] = int(user[1][1])
        if aim == UP:
            location[1] -= userPointerSpacer
        elif aim == DOWN:
            location[1] += userPointerSpacer
        elif aim == LEFT:
            location[0] -= userPointerSpacer
        elif aim == RIGHT:
            location[0] += userPointerSpacer
        elif aim == UPRIGHT:
            location[1] -= userPointerSpacer
            location[0] += userPointerSpacer
        elif aim == DOWNRIGHT:
            location[1] += userPointerSpacer
            location[0] += userPointerSpacer
        elif aim == UPLEFT:
            location[1] -= userPointerSpacer
            location[0] -= userPointerSpacer
        elif aim == DOWNLEFT:
            location[1] += userPointerSpacer
            location[0] -= userPointerSpacer

        
        # Draw the white background onto the surface.
        windowSurface.fill(WHITE)


        pygame.draw.circle(windowSurface, user[0], (int(user[1][0]), int(user[1][1])), int(user[2]), int(user[3]))
        pygame.draw.circle(windowSurface, user[4], (int(location[0]), int(location[1])), int(user[6]), int(user[7]))
##        for b in boxes:
##            # Move the box data structure.
##            if b['dir'] == DOWNLEFT:
##                b['rect'].left -= MOVESPEED
##                b['rect'].top += MOVESPEED
##            if b['dir'] == DOWNRIGHT:
##                b['rect'].left += MOVESPEED
##                b['rect'].top += MOVESPEED
##            if b['dir'] == UPLEFT:
##                b['rect'].left -= MOVESPEED
##                b['rect'].top -= MOVESPEED
##            if b['dir'] == UPRIGHT:
##                b['rect'].left += MOVESPEED
##                b['rect'].top -= MOVESPEED
##
### Check whether the box has moved out of the window.
##            if b['rect'].top < 0:
##                # The box has moved past the top.
##                if b['dir'] == UPLEFT:
##                    b['dir'] = DOWNLEFT
##                if b['dir'] == UPRIGHT:
##                    b['dir'] = DOWNRIGHT
##            if b['rect'].bottom > WINDOWHEIGHT:
##                # The box has moved past the bottom.
##                if b['dir'] == DOWNLEFT:
##                    b['dir'] = UPLEFT
##                if b['dir'] == DOWNRIGHT:
##                    b['dir'] = UPRIGHT
##            if b['rect'].left < 0:
##                # The box has moved past the left side.
##                if b['dir'] == DOWNLEFT:
##                    b['dir'] = DOWNRIGHT
##                if b['dir'] == UPLEFT:
##                    b['dir'] = UPRIGHT
##
##            if b['rect'].right > WINDOWWIDTH:
##                # The box has moved past the right side.
##                if b['dir'] == DOWNRIGHT:
##                    b['dir'] = DOWNLEFT
##                if b['dir'] == UPRIGHT:
##                    b['dir'] = UPLEFT
##
##            # Draw the box onto the surface.
##            #pygame.draw.rect(windowSurface, b['color'], b['rect'])

            # Draw the window onto the screen.
    pygame.display.update()
    time.sleep(0.02)
