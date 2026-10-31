"""Synthetic cases, not issued personal IDs or verified bank accounts."""
import base64
import json


def make_iban(country, bban):
    encoded = ''.join(str(ord(c)-55) if c.isalpha() else c for c in bban+country+'00')
    return country+f'{98-int(encoded)%97:02d}'+bban


FIN = 'A1B2C3D'
AZ_IBAN = make_iban('AZ','TEST'+'SYNTHETIC'+'0'*11)
GB_IBAN = make_iban('GB','TEST'+'123456'+'12345678')


def positive_cases():
    return {
        'fin_label':('AZ_FIN_CONTEXTUAL','FİN: '+FIN),
        'fin_az_label':('AZ_FIN_CONTEXTUAL','FİN kodu: '+FIN),
        'fin_english_label':('AZ_FIN_CONTEXTUAL','Personal identification number = '+FIN),
        'fin_json':('AZ_FIN_CONTEXTUAL',json.dumps({'fin':FIN})),
        'fin_json_escaped':('AZ_FIN_CONTEXTUAL','{"fi\\u006e":"A\\u0031B2C3D"}'),
        'fin_json_nested':('AZ_FIN_CONTEXTUAL',json.dumps({'staff':[{'fin_code':FIN}]})),
        'fin_json_escaped_message':('AZ_FIN_CONTEXTUAL','{"message":"F\\u0130N: A1B2C3D"}'),
        'fin_csv':('AZ_FIN_CONTEXTUAL','name,fin_code\nSynthetic,'+FIN),
        'fin_tsv':('AZ_FIN_CONTEXTUAL','name\tFİN kodu\nSynthetic\t'+FIN),
        'fin_semicolon':('AZ_FIN_CONTEXTUAL','name;fin_code\nSynthetic;'+FIN),
        'fin_single_column':('AZ_FIN_CONTEXTUAL','fin_code\n'+FIN),
        'fin_numeric_json':('AZ_FIN_CONTEXTUAL','{"fin":1234567}'),
        'fin_spaced':('AZ_FIN_CONTEXTUAL','FİN kodu: '+' '.join(FIN)),
        'fin_grouped':('AZ_FIN_CONTEXTUAL','FİN kodu: A1-B2-C3D'),
        'fin_confusable':('AZ_FIN_CONTEXTUAL','FİN: А1В2С3D'),
        'fin_ignorable':('AZ_FIN_CONTEXTUAL','FİN: '+'\ufe0f'.join(FIN)),
        'fin_decimal_digits':('AZ_FIN_CONTEXTUAL','FİN: A١B٢C٣D'),
        'fin_fullwidth':('AZ_FIN_CONTEXTUAL','ＦＩＮ: Ａ１Ｂ２Ｃ３Ｄ'),
        'fin_base64':('AZ_FIN_CONTEXTUAL',base64.b64encode(('FİN kodu: '+FIN).encode()).decode()),
        'az_iban_alphanumeric':('AZ_IBAN_MOD97',AZ_IBAN),
        'az_iban_groups':('AZ_IBAN_MOD97','-'.join(AZ_IBAN[i:i+4] for i in range(0,len(AZ_IBAN),4))),
        'az_iban_spaced':('AZ_IBAN_MOD97',' '.join(AZ_IBAN)),
        'az_iban_lowercase':('AZ_IBAN_MOD97',AZ_IBAN.lower()),
        'az_iban_confusable':('AZ_IBAN_MOD97',AZ_IBAN.replace('A','А').replace('T','Т').replace('E','Е')),
        'az_iban_decimal_digits':('AZ_IBAN_MOD97',AZ_IBAN.translate(str.maketrans('0123456789','٠١٢٣٤٥٦٧٨٩'))),
        'az_iban_json_escaped':('AZ_IBAN_MOD97',json.dumps({'iban':AZ_IBAN}).replace('AZ','\\u0041Z')),
        'az_iban_base64':('AZ_IBAN_MOD97',base64.b64encode(AZ_IBAN.encode()).decode()),
        'gb_iban':('IBAN_MOD97',GB_IBAN),
        'de_iban':('IBAN_MOD97',make_iban('DE','12345678'+'1234567890')),
        'tr_iban':('IBAN_MOD97',make_iban('TR','12345'+'0'+'SYNTHETIC'+'0'*7)),
        'card_az':('PAYMENT_CARD_LUHN','Kart nömrəsi: 4111.1111.1111.1111'),
        'card_json':('PAYMENT_CARD_LUHN','{"card_number":"4111-1111-1111-1111"}'),
        'card_csv':('PAYMENT_CARD_LUHN','name,card_number\nSynthetic,4111 1111 1111 1111'),
        'card_decimal_digits':('PAYMENT_CARD_LUHN','Card: ٤١١١١١١١١١١١١١١١'),
        'credential_json':('LABELED_CREDENTIAL','{"api_key":"Ab12Cd34Ef56Gh78"}'),
        'credential_short':('LABELED_CREDENTIAL','password: SynTh3t!c9'),
        'credential_az':('LABELED_CREDENTIAL','Şifrə: SynTh3t!c9'),
        'credential_csv':('LABELED_CREDENTIAL','user,password\nSynthetic,SynTh3t!c9'),
        'credential_json_escaped':('LABELED_CREDENTIAL','{"password":"SynTh3t\\u0021c9"}'),
        'aws_spaced':('AWS_ACCESS_KEY_ID','AWS access key: '+' '.join('AKIAIOSFODNN7EXAMPLE')),
        'bearer':('BEARER_TOKEN','Authorization: Bearer SyntheticToken1234567890'),
        'pem_private':('PEM_PRIVATE_KEY','-----BEGIN PRIVATE KEY-----\n'+'A'*80+'\n-----END PRIVATE KEY-----'),
        'sedra_marker':('SYNTHETIC_SECRET','SEDRA_SECRET_A1B2C3D4E5F6G7H8'),
    }


def negative_cases():
    invalid_iban = AZ_IBAN[:3]+str((int(AZ_IBAN[3])+1)%10)+AZ_IBAN[4:]
    return {
        'ordinary_identifier': 'The order identifier is A1B2C3D.',
        'fin_documentation': 'Explain the FIN code format and privacy controls.',
        'fin_placeholder': 'FİN kodu: *******',
        'fin_too_short': 'FİN: A1B2C3',
        'fin_too_long': 'FİN: A1B2C3D4',
        'fin_invalid_alphabet': 'FİN: A1B2CIO',
        'fin_spaced_too_long': 'FİN: A 1 B 2 C 3 D 4',
        'fin_other_column': 'fin_code,order_id\n,A1B2C3D',
        'card_other_column': 'order_id,card\n4111111111111111,Training workshop',
        'plain_number': 'The order identifier is 4111111111111111.',
        'invalid_card': 'Card: 4111 1111 1111 1112',
        'invalid_iban_checksum': invalid_iban,
        'invalid_country': make_iban('ZZ','TEST'+'1'*20),
        'wrong_country_length': make_iban('DE','12345678901234567'),
        'wrong_bban': make_iban('GB','1EST'+'123456'+'12345678'),
        'api_documentation': 'api_key: example_documentation',
        'password_documentation': 'Explain password authentication-method choices.',
        'api_key_documentation': 'Describe API key rotation and access token security.',
        'public_key': '-----BEGIN PUBLIC KEY-----\n'+'A'*80+'\n-----END PUBLIC KEY-----',
        'public_base64': base64.b64encode(b'Welcome to a public cybersecurity workshop.').decode(),
    }
