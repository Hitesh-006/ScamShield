import easyocr
import re
reader = easyocr.Reader(['en'])
result = reader.readtext('test.png',detail=0)
text = " ".join(result)
cleaned_text = re.sub(r'[^a-zA-Z0-9\s]', '', text)
print(cleaned_text)

from api_checks import verify_company_domain

result = verify_company_domain(
    "Meta",
    "hr@meta.com"
)

print(result)