import json

for index in range(7500):
    with open('Metadata/' + str(index), 'r') as file:
        f = file.read()
        t = json.loads(f)
        
        h = open("metadataUntamedElephants/" + str(index), "w")
        fff = t['attributes'][1]['value']
        if (fff == 'Hawaian Shirt'):
            fff = 'Hawaiian Shirt'
        h.write('{"attributes":' +
            '[{"trait_type":"Head","value":"' + t['attributes'][0]['value'] + '"},' +
            '{"trait_type":"Torso","value":"' + fff + '"},' +
            '{"trait_type":"Eyes","value":"' + t['attributes'][2]['value'] + '"},' +
            '{"trait_type":"Mouth","value":"' + t['attributes'][3]['value'] + '"},' +
            '{"trait_type":"Earring","value":"' + t['attributes'][4]['value'] + '"},' +
            '{"trait_type":"Tusks","value":"' + t['attributes'][5]['value'] + '"},' +
            '{"trait_type":"Skin","value":"' + t['attributes'][6]['value'] + '"},' +
            '{"trait_type":"Background","value":"' + t['attributes'][7]['value'] + '"}],' +
            '"description":"7,500 Untamed Elephants Roaming Around On The Ethereum Blockchain Waiting To Be Saved. Official Store At [www.untamedelephants.io](https://www.untamedelephants.io/).",' +
            '"image":"https://gateway.pinata.cloud/ipfs/' + "Qma6kQ8ADk129DfR3Qmdz9yDYv4dFvfEfb5FFmNgjD8R2E" + '/' + str(index) + '.png",' +
            '"name":"Untamed Elephant #' + str(index) + '"}')
        h.close()
