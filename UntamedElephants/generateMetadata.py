

for x in range(1):
    f = open("metaHidden/" + str(x), "w")
    f.write('{"attributes":' +
            '[{"trait_type":"Head","value":"Cofee"},' +
            '{"trait_type":"Torso","value":"asd"},' +
            '{"trait_type":"Eyes","value":"hyt"},' +
            '{"trait_type":"Mouth","value":"gsdg"},' +
            '{"trait_type":"Earring","value":"bvcb"},' +
            '{"trait_type":"Tusks","value":"yy"},' +
            '{"trait_type":"Skin","value":"dbf"},' +
            '{"trait_type":"Background","value":"wtwf"}],' +
            '"description":"7,500 Untamed Elephants Roaming Around On The Ethereum Blockchain Waiting To Be Saved. Official Store At [www.untamedelephants.io](https://www.untamedelephants.io/).",' +
            '"image":"https://untamedelephants.io/metaHidden/hidden.gif",' +
            '"name":"Untamed Elephant #' + str(x) + '"}')
    f.close()
