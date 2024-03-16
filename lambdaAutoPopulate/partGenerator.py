import json, shortuuid, datetime, os
from decimal import Decimal
from boto3.dynamodb.types import TypeSerializer

part = {
        'PK': 'PART#COMPANY#3Fwa2RJvVn7HXSdfiBL3i2',
        'SK': 'COMPANY#3Fwa2RJvVn7HXSdfiBL3i2#LATEST#TRUE#ACTIVE#TRUE#NAME#Part_1#REVISION#A#PART#VJ63LEx4vMiFpJyVTYDMWX',
        'companyId': '3Fwa2RJvVn7HXSdfiBL3i2',
        'id': 'VJ63LEx4vMiFpJyVTYDMWX',
        'name': 'Part 1',
        'revision': 'A',
        'akaName': 'Part 1',
        'cavities': '1',
        'intervalMinutes': '30',
        'previousId': '3Fwa2RJvVn7HXSdfiBL3i2',
        'latest': 'true',
        'description': 'Part 1',
        'active': 'true',
        'created': '2020-01-01T00:00:00.000',
        'updated': '2020-01-01T00:00:00.000',
        'updateNote': 'Part 1',
        'dimensions': [{"name":"string", "akaName":"string", "type":"string", "nominal":"string", "upper":"string", "lower":"string", "unit":"string", "updated":"2020-01-01T00:00:00.000", "updatedNote":"string", "notes":"string"}],
    }

company_id = '3Fwa2RJvVn7HXSdfiBL3i2'
parts_file = os.path.join(os.path.dirname(__file__), 'parts.json')

with open(parts_file, 'w') as outfile:

    for i in range(20):
        # Create dummy parts in the same format as the part above
        # Generate a random uuid for the part id
        part['id'] = shortuuid.uuid()
        # Generate a random uuid for the previousId
        part['previousId'] = shortuuid.uuid()

        # Generate a random name for the part and make it seem like a real part number
        part['name'] = 'Part ' + str(i) + ' ' + "Name"

        # Generate a random akaName for the part
        part['akaName'] = 'AKA ' + str(i) + ' ' + "Name"

        # Generate a random description for the part
        part['description'] = 'Part ' + str(i) + ' ' + "Description"

        # Generate a random revision for the part
        part['revision'] = str(i)

        # Generate  cavities for the part
        part['cavities'] = "4"

        # Generate  intervalMinutes for the part    
        part['intervalMinutes'] = "30"

        # Generate a random updateNote for the part
        part['updateNote'] = 'Part ' + str(i) + ' ' + "Update Note"

        # Generate a random created for the part
        part['created'] = datetime.datetime.now().isoformat()

        # Generate a random updated for the part
        part['updated'] = datetime.datetime.now().isoformat()

        PK = 'PART#COMPANY#' + company_id
        SK = 'COMPANY#' + company_id + '#LATEST#TRUE#ACTIVE#TRUE#NAME#' + part['name'].upper().replace(" ", "_") + '#REVISION#' + part['revision'] + '#PART#' + part['id']

        part['PK'] = PK
        part['SK'] = SK

        # Generate 3 dimensions for the part
        dimensions = []
        types = ["bounded", "max", "min", "limits"]
        for j, type_ in enumerate(types):
            dimension = {"name":"Dimension " + str(j), "akaName":"Dimension " + str(j), "type":type_, "nominal": 1.0, "upper":1.5, "lower":0.6, "unit":"in", "updated":datetime.datetime.now().isoformat(), "updatedNote":"Updated Note " + str(j), "notes":"Notes " + str(j)}
            for key, value in dimension.items():
                if key == 'nominal' or key == 'upper' or key == 'lower':
                    if value:
                        dimension[key] = Decimal(str(value))
            dimensions.append(dimension)


        part['dimensions'] = dimensions

        outfile.write("db.table.put_item(Item=")

        # Serialize the part to json to correct dynamodb format
        serilizer = TypeSerializer()
        serialized_part = serilizer.serialize(part)

        json.dump(serialized_part, outfile)

        outfile.write(')\n')