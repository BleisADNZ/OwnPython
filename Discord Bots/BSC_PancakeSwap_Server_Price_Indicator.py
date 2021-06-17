import discord
import os
from dotenv import load_dotenv
from web3 import Web3
import requests
import time
import asyncio
#import base64

load_dotenv()

client = discord.Client()
member = discord.Member

#auth = base64.b64encode((os.getenv('PROUSER') + ':' + os.getenv('PROPASS')).encode('ascii')).decode('ascii')

#s = requests.Session()
#s.headers.update({'authorization': 'Basic ' + auth })

w3 = Web3(Web3.HTTPProvider('https://bsc-dataseed4.defibit.io/'))
#w3 = Web3(Web3.HTTPProvider(os.getenv('PROVIDER'), session=s))

bnb = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"
pair = ""
#test 0x0eD7e52944161450477ee417DE9Cd3a859b14fD0
pairWithUsdt = "0x58f876857a02d6762e0101bb5c46a8c1ed44dc16"

API_ENDPOINT = "https://api.bscscan.com/api?module=contract&action=getabi&address="


rBnb = requests.get(url = (API_ENDPOINT+bnb))
responseBNB = rBnb.json()

condition = False
global token0Decimal
global token1Decimal
global token0Symbol
global token1Symbol
global token0
global token1
global instance
global response
token0Decimal = 0
token1Decimal = 0
token0Symbol = ""
token1Symbol = ""
token0 = ''
token1 = ''

response = ''

helpInfo = '\n\nPlease, to initiate the bot follow *help'

instance = w3.eth.contract(
        address=Web3.toChecksumAddress(bnb),
        abi=responseBNB["result"]
      )

@client.event
async def on_ready():
    print('We have logged in as {0.user}'.format(client))

#async def shutdown(message):
#    await message.send(asyncio.all_tasks())
#    for task in asyncio.all_tasks():
#        task.cancel()

@client.event
async def on_message(message):
    global condition
    if message.author == client.user:
        return
    if message.content.startswith('*help'):
        await message.channel.send('BSC PancakeSwap Price Indicator v0.0.1\n' +
        '\nThis bot will update its nickname to contain the price of a specific token on the BSC if the pair is BNB/<specific token>\n\nTo start find the pair address of the token you want the price of, then proceed to run the following\n\n- *setpair <pair address> - this command will set the pair and verify if its valid. You will be able to check by using the commands *pair *token0 *token1\n- *decimals - this command will run to update the specific decimals of your pair. You will be able to check by using the commands  *token0Dec and *token1Dec\n- *symbols - this command will run to update the specific symbols of your pair. You will be able to check by using the commands  *token0Sym and *token1Sym\n- *run - this command will start the bot to update its nickname\n- *stop - this command will stop the bot from updating the nickname\n\n\n\nI hope you like the bot!\nMade by Bleiserman with <3')
    if message.content.startswith('*isconnected?'):
        await message.channel.send(w3.isConnected())
    if message.content.startswith('*run'):
        if (condition == False):
          try:
            await message.channel.send('Activated price reload')
            condition = True
            asyncio.run(await runReloads(message))
          except:
            condition = False
            await message.channel.send('Deactivated price reload')
        else:
          await message.channel.send('Already running')
    if message.content.startswith('*stop'):
        if (condition == True):
          condition = False
          #await shutdown(message.channel)
        else:
          await message.channel.send('Not running')
    if message.content.startswith('*setpair'):
        await setPairAndTokens(message)
    if message.content.startswith('*decimals'):
        await getTokenDecimals(message)
    if message.content.startswith('*symbols'):
        await getTokenSymbols(message)
    if message.content.startswith('*pair'):
        if (pair == ""):
          await message.channel.send('Empty pair address' + helpInfo)
        else:
          await message.channel.send(pair)
    if message.content.startswith('*token0'):
        if (token0 == ""):
          await message.channel.send('Empty token0 address' + helpInfo)
        else:
          await message.channel.send(token0)
    if message.content.startswith('*token1'):
        if (token1 == ""):
          await message.channel.send('Empty token1 address' + helpInfo)
        else:
          await message.channel.send(token1)
    if message.content.startswith('*token0Dec'):
        if (token0Decimal == 0):
          await message.channel.send('Empty decimals' + helpInfo)
        else:
          await message.channel.send(token0Decimal)
    if message.content.startswith('*token1Dec'):
        if (token1Decimal == 0):
          await message.channel.send('Empty decimals' + helpInfo)
        else:
          await message.channel.send(token1Decimal)
    if message.content.startswith('*token0Sym'):
        if (token0Decimal == 0):
          await message.channel.send('Empty symbols' + helpInfo)
        else:
          await message.channel.send(token0Symbol)
    if message.content.startswith('*token1Sym'):
        if (token1Decimal == 0):
          await message.channel.send('Empty symbols' + helpInfo)
        else:
          await message.channel.send(token1Symbol)


async def setPairAndTokens(message):
  global pair
  content = message.content
  if (len(content[9:]) == 42):
    pair = content[9:]
    await message.channel.send('Its a valid address...')
  try:
    if (pair != ''):
      global token0Decimal
      global token1Decimal
      global token0
      global token1
      global instance
      global response
      r = requests.get(url = (API_ENDPOINT+pair))
      response = r.json()
    # Getting reserves from token/BNB pair as 'reserves'
      instance = w3.eth.contract(
        address=Web3.toChecksumAddress(pair),
        abi=response["result"]
      )
        # Token0 address
      token0 = instance.functions.token0().call()
        # Token1 address
      token1 = instance.functions.token1().call()
      await message.channel.send('Pair added and token addresses added')
  except:
    pair = ''
    await message.channel.send('It actually is not a pair address')

  

async def getTokenDecimals(message):
  if (pair != ''):
    global token0Decimal
    global token1Decimal
    global token0
    global token1

  # Getting reserves from token/BNB pair as 'reserves'
  
      # Token 0 Decimals 
    token0Decimal = w3.eth.contract(
      address=Web3.toChecksumAddress(token0),
      abi=responseBNB["result"]
    ).functions.decimals().call()
      # Token 1 Decimals 
    token1Decimal = w3.eth.contract(
      address=Web3.toChecksumAddress(token1),
      abi=responseBNB["result"]
    ).functions.decimals().call()
    await message.channel.send('Token decimals added')
  else:
    await message.channel.send("Pair wasn't added yet" + helpInfo)

async def getTokenSymbols(message):
  if (pair != ''):
    global token0Symbol
    global token1Symbol
    global token0
    global token1

  # Getting reserves from token/BNB pair as 'reserves'
  
      # Token 0 Decimals 
    token0Symbol = w3.eth.contract(
      address=Web3.toChecksumAddress(token0),
      abi=responseBNB["result"]
    ).functions.symbol().call()
      # Token 1 Decimals 
    token1Symbol = w3.eth.contract(
      address=Web3.toChecksumAddress(token1),
      abi=responseBNB["result"]
    ).functions.symbol().call()
    await message.channel.send('Token symbols added')
  else:
    await message.channel.send("Pair wasn't added yet" + helpInfo)

        
async def runReloads(message):
  if (token0Decimal != 0 or token0Symbol != ''):
    global condition
    global instance
    global response
    while condition:

        # Getting reserves from token/BNB pair as 'reserves'
        reserves = instance.functions.getReserves().call()

        # Getting reserves from BNB/BUSDT pair as 'reserves2'
        reserves2 = w3.eth.contract(
          address=Web3.toChecksumAddress(pairWithUsdt),
          abi=response["result"]
        ).functions.getReserves().call()
        # Token0 address
        token0BNB = '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c'
        # Token1 address
        #token1BUSDT = '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56'
        # Token 0 Decimals 
        token0DecimalBNB = 18
        # Token 1 Decimals 
        token1DecimalBUSDT = 18


        balance0 = (reserves2[1] / (10**token1DecimalBUSDT)) / (reserves2[0] / (10**token0DecimalBNB))

        if (token0BNB != token0):
          balance = balance0 / ((reserves[0] / (10**token0Decimal)) / (reserves[1] / (10**token1Decimal)))
          newNick = '' + str(round(balance, 2)) + '$ /' + token0Symbol
        else:
          balance = balance0 / ((reserves[1] / (10**token0Decimal)) / (reserves[0] / (10**token1Decimal)))
          newNick = '' + str(round(balance, 2)) + '$ /' + token1Symbol
        

        #print(newNick)
        await message.guild.get_member(client.user.id).edit(nick=newNick)
        await asyncio.sleep(15)
  else:
    await message.channel.send("Pair or token decimals/symbol weren't added yet" + helpInfo)



client.run(os.getenv('TOKEN'))
