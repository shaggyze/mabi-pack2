import re

with open('src/lib.rs', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('let session: SessionInfo = result.session.into();', 'let session: SessionInfo = result.session.unwrap().into();')

with open('src/lib.rs', 'w', encoding='utf-8') as f:
    f.write(content)

print("Done")
