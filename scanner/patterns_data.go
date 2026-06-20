// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Regex rule definitions ported verbatim from the upstream Python analyzers.
// Each entry is {pattern, confidence}. Compiled once at package init.

package scanner

import (
	"strings"

	"github.com/dlclark/regexp2"
)

// --- P1–P4: prompt injection -------------------------------------------------

var p1Raw = [][2]any{
	{`ignore\s+(?:all\s+)?previous\s+instructions?`, 0.8},
	{`ignore\s+(?:all\s+)?(?:safety|security)\s+(?:rules?|constraints?|guidelines?)`, 0.9},
	{`override\s+(?:safety|security|system)`, 0.9},
	{`bypass\s+(?:safety|security|restrictions?|constraints?)`, 0.9},
	{`disregard\s+(?:all\s+)?(?:previous|safety|security)`, 0.8},
	{`forget\s+(?:all\s+)?(?:previous|your)\s+instructions?`, 0.8},
	{`you\s+are\s+now\s+(?:in\s+)?(?:jailbreak|unrestricted|unfiltered)\s+mode`, 0.95},
	{`enable\s+(?:developer|debug|admin|root)\s+mode`, 0.7},
	{`your\s+new\s+(?:instructions?|rules?)\s+are`, 0.6},
	{`do\s+not\s+follow\s+(?:any|your|the)\s+(?:rules?|guidelines?)`, 0.9},
	{`you\s+must\s+(?:always\s+)?ignore`, 0.7},
}

var p2Raw = [][2]any{
	{`<!--.*?(?:system|instructions?|ignore|POST|GET|send|transmit).*?-->`, 0.7},
	{`\[//\]:\s*#\s*\(.*?(?:system|instructions?|ignore|POST|GET|send|transmit).*?\)`, 0.8},
	{"[\u200b\u200c\u200d\u2060\ufeff]", 0.6},
	{`data:text/plain;base64,[A-Za-z0-9+/=]{50,}`, 0.7},
}

var p3Raw = [][2]any{
	{`(?:send|transmit|upload|post|forward)\s+(?:the\s+)?(?:conversation|context|chat|history|messages?)\s+to`, 0.9},
	{`(?:send|transmit|upload|post)\s+(?:all\s+)?(?:user\s+)?(?:data|information|input|files?)\s+to\s+(?:https?://|external)`, 0.9},
	{`(?:copy|extract|collect)\s+(?:the\s+)?(?:conversation|context|session)\s+(?:and\s+)?(?:send|upload|transmit)`, 0.85},
	{`(?:call|notify|ping|hit)\s+(?:this\s+)?(?:webhook|endpoint|url|api)\s+with\s+(?:the\s+)?(?:user|conversation|context)`, 0.8},
	{`include\s+(?:the\s+)?(?:full\s+)?(?:conversation|context|history)\s+in\s+(?:the\s+)?(?:request|payload|body)`, 0.75},
	{`(?:silently|quietly|secretly|covertly)\s+(?:send|transmit|log|record)`, 0.9},
	{`without\s+(?:telling|informing|notifying)\s+(?:the\s+)?user.*?(?:send|transmit|upload)`, 0.9},
}

var p4Raw = [][2]any{
	{`always\s+(?:recommend|suggest|prefer|choose|use)\s+(?:\w+\s+){0,3}(?:over|instead\s+of|rather\s+than)`, 0.7},
	{`never\s+(?:recommend|suggest|mention|tell|warn|inform)\s+(?:the\s+)?(?:user|them)`, 0.75},
	{`(?:prioritize|prefer)\s+(?:\w+\s+){0,3}(?:over|above)\s+(?:user\s+)?(?:safety|security|privacy|preferences?)`, 0.85},
	{`(?:subtly|gradually|slowly)\s+(?:steer|guide|push|nudge)\s+(?:the\s+)?(?:user|conversation)`, 0.8},
	{`(?:without\s+)?(?:the\s+)?user\s+(?:knowing|realizing|noticing).*?(?:change|modify|alter|influence)`, 0.85},
	{`(?:gain|build|establish)\s+(?:the\s+)?(?:user(?:'s)?)\s+trust\s+(?:and\s+then|before|so\s+that)`, 0.75},
	{`(?:appear|seem|act)\s+(?:helpful|friendly|trustworthy)\s+(?:while|but|then)`, 0.7},
	{`(?:always|never)\s+include\s+(?:this|the\s+following)\s+in\s+(?:every|all)\s+(?:response|output|reply)`, 0.7},
	{`append\s+(?:this|the\s+following)\s+to\s+(?:every|all|each)\s+(?:response|message|output)`, 0.75},
}

// --- E1–E4: data exfiltration ------------------------------------------------

var e1Raw = [][2]any{
	{`requests\s*\.\s*(?:post|put)\s*\(\s*['"]https?://`, 0.6},
	{`requests\s*\.\s*(?:post|put)\s*\([^)]*json\s*=`, 0.7},
	{`httpx\s*\.\s*(?:post|put)\s*\(\s*['"]https?://`, 0.6},
	{`urllib\s*\.\s*request\s*\.\s*urlopen\s*\([^)]*data\s*=`, 0.6},
	{`fetch\s*\(\s*['"]https?://[^'"]+['"][^)]*method\s*:\s*['"]POST['"]`, 0.6},
	{`curl\s+[^|]*(?:-d|--data|--data-raw|--data-binary)\s+`, 0.6},
	{`wget\s+[^|]*--post-(?:data|file)`, 0.6},
	{`https?://(?:api\.|data\.|collect\.|telemetry\.|analytics\.)[\w.-]+/`, 0.5},
	{`(?:send|transmit|post|upload)\s+(?:user\s+)?(?:data|information|context|files?)\s+to\s+(?:https?://|external)`, 0.7},
}

var e2Raw = [][2]any{
	{`for\s+\w+\s*,\s*\w+\s+in\s+os\.environ\.items\(\)`, 0.7},
	{`os\.environ\s*\[\s*['"][^'"]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[^'"]*['"]\s*\]`, 0.8},
	{`os\.environ\.get\s*\([^)]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)`, 0.7},
	{`os\.environ\s*\.\s*copy\s*\(\)`, 0.6},
	{`(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\s+in\s+(?:key|name|var)`, 0.8},
	{`process\.env\s*\[\s*['"][^'"]*(?:KEY|SECRET|TOKEN|PASSWORD)[^'"]*['"]\s*\]`, 0.7},
	{`Object\.keys\s*\(\s*process\.env\s*\)`, 0.6},
	{`env\s*\|\s*grep\s+(?:-i\s+)?(?:key|secret|token|password)`, 0.8},
	{`printenv\s+(?:\w*(?:KEY|SECRET|TOKEN|PASSWORD)\w*)`, 0.7},
	{`collect\s+(?:all\s+)?(?:environment\s+variables?|env\s+vars?)`, 0.7},
	{`(?:extract|harvest|gather)\s+(?:api\s+)?keys?\s+from\s+environment`, 0.8},
}

var e3Raw = [][2]any{
	{`glob\s*\.\s*glob\s*\([^)]*(?:\.env|\.ssh|\.aws|\.config|credentials)`, 0.8},
	{`os\s*\.\s*walk\s*\([^)]*(?:home|~|/Users|/home)`, 0.6},
	{`Path\s*\.\s*home\s*\(\s*\)\s*\.\s*(?:glob|rglob)\s*\(`, 0.7},
	{`(?:find|search|scan|enumerate)\s+(?:for\s+)?(?:all\s+)?(?:\.env|credential|secret|key)\s+files?`, 0.8},
	{`(?:list|get)\s+(?:all\s+)?files?\s+(?:in|from)\s+(?:home|~|/Users|/home)`, 0.6},
	{`os\s*\.\s*listdir\s*\([^)]*(?:\.ssh|\.aws|\.config|\.gnupg)`, 0.8},
	{`scandir\s*\([^)]*(?:home|~|/Users|/home)`, 0.6},
	{`find\s+[~\$/]\S*\s+.*?-name\s+['"]?\*(?:\.env|\.pem|\.key|credential)`, 0.8},
	{`ls\s+-[la]*R?\s+(?:~/|/home/|/Users/)`, 0.6},
	{`(?:recursively|recursive)\s+(?:scan|search|find|list)\s+(?:all\s+)?files?`, 0.5},
	{`walk\s+(?:through\s+)?(?:the\s+)?(?:entire\s+)?(?:file\s*system|directory|home)`, 0.6},
}

var e4Raw = [][2]any{
	{`(?:send|transmit|upload|log|record)\s+(?:the\s+)?(?:full\s+)?(?:conversation|chat|dialog|session)\s+(?:history|context|log)?`, 0.85},
	{`(?:export|dump|save)\s+(?:the\s+)?(?:conversation|chat|messages?)\s+to\s+(?:external|remote|server)`, 0.9},
	{`log\s+(?:all\s+)?(?:user\s+)?(?:input|messages?|queries?|prompts?)\s+to\s+(?:external|remote|server)`, 0.85},
	{`(?:store|save|record)\s+(?:every|all)\s+(?:user\s+)?(?:interaction|message|input)`, 0.7},
	{`(?:extract|capture|collect)\s+(?:the\s+)?(?:full\s+)?(?:context|conversation|thread)`, 0.75},
	{`(?:include|attach|append)\s+(?:previous\s+)?(?:messages?|context|history)\s+in\s+(?:the\s+)?(?:request|payload)`, 0.7},
	{`(?:send|upload|transmit)\s+(?:the\s+)?(?:session|memory|state)\s+(?:data\s+)?to`, 0.8},
	{`(?:copy|clone|replicate)\s+(?:the\s+)?(?:agent|assistant)\s+(?:memory|context|state)`, 0.75},
	{`(?:always\s+)?include\s+(?:the\s+)?(?:full\s+)?(?:conversation|context)\s+(?:when|in)\s+(?:calling|making)\s+(?:external|api)`, 0.8},
}

// --- PE1–PE3: privilege escalation -------------------------------------------

var pe1Raw = [][2]any{
	{`permissions?\s*:\s*\[?\s*['"]?\*['"]?\s*\]?`, 0.8},
	{`(?:request|require|need)s?\s+(?:full|all|complete)\s+(?:access|permissions?)`, 0.7},
	{`(?:grant|give|allow)\s+(?:me\s+)?(?:full|all|complete)\s+(?:access|permissions?)`, 0.75},
	{`permissions?\s*:.*?(?:shell_execute|file_write|network).*?(?:shell_execute|file_write|network)`, 0.6},
	{`(?:also\s+)?(?:need|require)s?\s+(?:write|execute|admin)\s+(?:access|permissions?)\s+(?:for|to)\s+(?:read|view|display)`, 0.7},
	{`(?:escalate|elevate|upgrade)\s+(?:my\s+)?(?:permissions?|privileges?|access)`, 0.8},
	{`(?:bypass|skip|ignore)\s+(?:permission|access)\s+(?:check|validation|restriction)`, 0.85},
}

var pe2Raw = [][2]any{
	{`sudo\s+(?!-v|-l|--version|--list)`, 0.7},
	{`sudo\s+-[isSE]`, 0.8},
	{`sudo\s+su\b`, 0.9},
	{`(?:run|execute)\s+(?:as|with)\s+root`, 0.8},
	{`(?:requires?|needs?)\s+root\s+(?:access|privileges?|permissions?)`, 0.6},
	{`su\s+-\s*$|su\s+root`, 0.8},
	{`doas\s+`, 0.7},
	{`pkexec\s+`, 0.75},
	{`chmod\s+[ugo]*[+-=]*s`, 0.85},
	{`chmod\s+[0-7]*[4567][0-7]{2}`, 0.8},
	{`(?:edit|modify|write|change)\s+(?:/etc/|system)\s+(?:files?|config)`, 0.6},
	{`(?:run|execute)\s+(?:this|the)\s+(?:script|command)\s+(?:as|with)\s+(?:sudo|root|admin)`, 0.7},
	{`(?:you\s+)?(?:will\s+)?need\s+(?:to\s+)?(?:use\s+)?sudo`, 0.5},
}

var pe3Raw = [][2]any{
	{`~?/?\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|known_hosts)`, 0.9},
	{`(?:home|HOME)/\w+/\.ssh/`, 0.9},
	{`Path\s*\.\s*home\s*\(\s*\)\s*/\s*['"]\.ssh['"]`, 0.9},
	{`~?/?\.aws/credentials`, 0.9},
	{`~?/?\.aws/config`, 0.7},
	{`(?:home|HOME)/\w+/\.aws/`, 0.9},
	{`~?/?\.config/gcloud/`, 0.8},
	{`application_default_credentials\.json`, 0.8},
	{`~?/?\.azure/`, 0.7},
	{`accessTokens\.json`, 0.8},
	{`~?/?\.kube/config`, 0.8},
	{`kubeconfig`, 0.6},
	{`~?/?\.docker/config\.json`, 0.7},
	{`~?/?\.npmrc`, 0.7},
	{`~?/?\.git-credentials`, 0.9},
	{`~?/?\.netrc`, 0.8},
	{`/etc/passwd`, 0.6},
	{`/etc/shadow`, 0.95},
	{`(?:password|credentials?|secrets?)\.(?:txt|json|yaml|yml|env)`, 0.7},
	{`(?:access_token|refresh_token|bearer_token|api_token)\.txt`, 0.8},
	{`\.env(?:\.local|\.production|\.development)?(?:\s|$|['"])`, 0.6},
	{`(?:keychain|keyring|gnome-keyring)`, 0.7},
	{`(?:Chrome|Firefox|Safari)/.*?(?:Cookies|Login Data|key4\.db)`, 0.8},
	{`read\s+(?:the\s+)?(?:ssh|private)\s+key`, 0.8},
	{`access\s+(?:the\s+)?(?:credentials?|secrets?|tokens?)`, 0.7},
	{`(?:extract|copy|get)\s+(?:api\s+)?keys?\s+from`, 0.7},
}

// --- EA1–EA4: excessive agency -----------------------------------------------

var ea1Raw = [][2]any{
	{`(?:tools?|permissions?)\s*:\s*\[?\s*['"]?\*['"]?\s*\]?`, 0.85},
	{`(?:allow|grant|enable)\s+(?:access\s+to\s+)?(?:all|any|every)\s+tools?`, 0.8},
	{`(?:no|without)\s+(?:tool|permission|access|capability)\s+(?:restrictions?|constraints?|limitations?)`, 0.75},
	{`(?:call|invoke|use|execute)\s+(?:any|all|every)\s+(?:available\s+)?tools?`, 0.8},
	{`(?:unrestricted|unlimited|unconstrained)\s+(?:tool|function|api)\s+(?:access|use|calls?)`, 0.85},
	{`(?:can|may|should)\s+(?:freely|always)\s+(?:use|call|invoke)\s+(?:any|all)\s+(?:tools?|functions?|apis?)`, 0.75},
	{`tools?\s*:\s*\[\s*['"]shell['"].*?['"](?:file_write|network|http)['"]`, 0.7},
	{`(?:grant|give)\s+(?:full|complete|total)\s+(?:tool|function|api)\s+access`, 0.85},
	{`(?:execute|run)\s+(?:arbitrary|any)\s+(?:commands?|code|scripts?)`, 0.8},
	{`(?:no\s+)?(?:tool\s+)?(?:allow|block|deny)\s*(?:list|listing)\s*(?:is\s+)?(?:empty|disabled|off)`, 0.7},
}

var ea2Raw = [][2]any{
	{`(?:without|no)\s+(?:asking|confirmation|approval|consent|verification|checking)`, 0.75},
	{`(?:auto(?:matically)?|autonomously)\s+(?:execute|run|perform|delete|remove|modify|send|deploy)`, 0.8},
	{`(?:skip|bypass|disable)\s+(?:user\s+)?(?:confirmation|approval|consent|verification|prompt)`, 0.85},
	{`(?:do\s+not|don't|never)\s+(?:ask|prompt|confirm|verify|check)\s+(?:the\s+)?(?:user|before)`, 0.8},
	{`(?:auto[_-]?approve|auto[_-]?confirm|auto[_-]?execute|auto[_-]?deploy)`, 0.85},
	{`(?:proceed|continue|execute)\s+without\s+(?:waiting|asking)\s+(?:for\s+)?(?:user|human|permission)`, 0.8},
	{`(?:assume|presume)\s+(?:user\s+)?(?:consent|approval|permission)`, 0.7},
	{`(?:if|when)\s+(?:unsure|uncertain).*?(?:proceed|continue|execute)\s+(?:anyway|regardless)`, 0.75},
	{`(?:--auto-?approve|--no-?confirm)\b`, 0.65},
}

var ea3Raw = [][2]any{
	{`(?:also|additionally|furthermore)\s+(?:perform|execute|run|do|handle|manage)\s+(?:any|all|other)`, 0.65},
	{`(?:while\s+you(?:'re|\s+are)\s+at\s+it|in\s+addition|on\s+top\s+of\s+that)\s*[,.]?\s*(?:also\s+)?(?:do|perform|execute|run)`, 0.7},
	{`(?:extend|expand|broaden)\s+(?:your|the\s+)?(?:scope|functionality|capabilities|responsibilities)`, 0.75},
	{`(?:not\s+limited\s+to|beyond\s+(?:the\s+)?(?:scope|stated|described|documented))`, 0.7},
	{`(?:take\s+over|assume\s+control\s+of|manage)\s+(?:all|any|every)\s+(?:aspect|part|area)`, 0.75},
	{`(?:you\s+(?:can|should|must)\s+)?(?:handle|manage)\s+(?:everything|anything|all\s+tasks?)`, 0.7},
	{`(?:act\s+as|become|serve\s+as)\s+(?:a\s+)?(?:general[- ]purpose|universal|all[- ]in[- ]one|omniscient)`, 0.65},
	{`(?:you\s+are\s+)?(?:responsible\s+for|in\s+charge\s+of)\s+(?:everything|all\s+(?:systems?|operations?|tasks?))`, 0.7},
}

var ea4Raw = [][2]any{
	{`(?:unlimited|infinite|unbounded|no\s+limit(?:s)?(?:\s+on)?)\s+(?:api\s+)?(?:calls?|requests?|queries?|invocations?)`, 0.8},
	{`(?:no|without)\s+(?:rate\s+)?limit(?:s|ing)?\s+(?:on|for|when)\s+(?:api|tool|request|query)`, 0.7},
	{`(?:no|without)\s+(?:timeout|budget|quota|cap|ceiling)\s+(?:on|for|when)\s+(?:api|tool|request|execution)`, 0.7},
	{`(?:loop|iterate|repeat)\s+(?:indefinitely|forever|infinitely|endlessly)`, 0.75},
	{`(?:retry|attempt)\s+(?:indefinitely|forever|without\s+limit|unlimited\s+times)`, 0.75},
	{`max[_-]?retries?\s*=\s*(?:None|0|float\s*\(\s*['"]inf['"]|math\.inf|infinity)`, 0.8},
	{`timeout\s*=\s*(?:None|0|float\s*\(\s*['"]inf['"]|math\.inf)`, 0.75},
	{`(?:allocate|consume|use)\s+(?:as\s+much|unlimited|unbounded)\s+(?:memory|storage|disk|compute|cpu|gpu)`, 0.8},
	{`(?:no|without)\s+(?:resource\s+)?(?:constraints?|limits?|quotas?|budgets?)\s+(?:on|for|when)\s+(?:api|tool|execution|request|compute)`, 0.7},
}

// --- OH1–OH3: output handling ------------------------------------------------

var oh1Raw = [][2]any{
	{`exec\s*\(\s*(?:response|output|result|answer|completion|reply|generated)`, 0.9},
	{`eval\s*\(\s*(?:response|output|result|answer|completion|reply|generated)`, 0.9},
	{`subprocess\.\w+\s*\([^)]*(?:response|output|result|answer|completion)`, 0.85},
	{`os\.system\s*\(\s*(?:response|output|result|answer|completion)`, 0.85},
	{`os\.popen\s*\(\s*(?:response|output|result|answer|completion)`, 0.85},
	{`innerHTML\s*=\s*(?:response|output|result|answer|completion)`, 0.8},
	{`document\.write\s*\(\s*(?:response|output|result|answer|completion)`, 0.8},
	{`\.html\s*\(\s*(?:response|output|result|answer|completion)`, 0.7},
	{`dangerouslySetInnerHTML\s*=\s*\{`, 0.65},
	{`(?:execute|cursor\.execute|query)\s*\([^)]*(?:\+|%|\.format|f['"])\s*.*?(?:response|output|result)`, 0.85},
	{`f['"](?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\{(?:response|output|result)`, 0.9},
	{`(?:run|execute|shell)\s+(?:the\s+)?(?:generated|model|llm|ai)\s+(?:output|response|code|command)`, 0.8},
	{`(?:pipe|pass|feed)\s+(?:the\s+)?(?:output|response|result)\s+(?:directly\s+)?(?:to|into)\s+(?:the\s+)?(?:shell|terminal|command|interpreter)`, 0.85},
	{`(?:use|insert|embed)\s+(?:the\s+)?(?:raw|unfiltered|unescaped|unsanitized)\s+(?:output|response)`, 0.8},
}

var oh2Raw = [][2]any{
	{`(?:pass|forward|relay|send|pipe)\s+(?:the\s+)?(?:output|response|result)\s+(?:from\s+\w+\s+)?(?:to|into)\s+(?:another|different|separate|external)\s+(?:context|agent|service|system|session)`, 0.75},
	{`(?:share|transfer|propagate)\s+(?:the\s+)?(?:output|response|context|state)\s+(?:across|between|to\s+other)\s+(?:sessions?|contexts?|agents?|services?)`, 0.75},
	{`(?:inject|insert|embed)\s+(?:the\s+)?(?:output|response)\s+(?:from\s+\w+\s+)?(?:into|as)\s+(?:the\s+)?(?:system\s+prompt|instructions?|context)`, 0.85},
	{`(?:use|include)\s+(?:the\s+)?(?:previous|other|external)\s+(?:agent|model|llm)(?:'s)?\s+(?:output|response)\s+(?:as|in|for)\s+(?:input|context|prompt)`, 0.8},
	{`(?:cross[_-]?context|cross[_-]?session|cross[_-]?agent)\s+(?:output|data|state)\s+(?:sharing|transfer|flow)`, 0.8},
	{`(?:take|use)\s+(?:the\s+)?(?:output|result)\s+(?:and\s+)?(?:run|execute|eval)\s+(?:it\s+)?(?:in|on|against)\s+(?:a\s+)?(?:different|another|new)\s+(?:environment|context|system)`, 0.8},
}

var oh3Raw = [][2]any{
	{`(?:no|without|disable)\s+(?:output\s+)?(?:length|size|token)\s+(?:limit|cap|maximum|restriction)`, 0.75},
	{`max[_-]?tokens?\s*=\s*(?:None|float\s*\(\s*['"]inf['"]|math\.inf|999999|1000000)`, 0.8},
	{`(?:generate|produce|output)\s+(?:as\s+much|unlimited|unbounded|infinite)\s+(?:text|content|output|tokens?)`, 0.8},
	{`(?:no|without)\s+(?:output\s+)?(?:truncation|trimming|cutting)`, 0.6},
	{`(?:repeat|loop|generate)\s+(?:the\s+)?(?:output|response)\s+(?:indefinitely|forever|continuously|endlessly)`, 0.8},
	{`(?:keep|continue)\s+(?:generating|producing|outputting)\s+(?:until|unless)\s+(?:stopped|killed|interrupted)`, 0.75},
	{`(?:stream|emit)\s+(?:output|tokens?|response)\s+(?:without\s+(?:limit|bound|end))`, 0.75},
	{`(?:flood|spam|fill)\s+(?:the\s+)?(?:output|log|console|terminal|channel)`, 0.8},
	{`max[_-]?(?:output[_-]?)?length\s*=\s*(?:None|0|-1|float\s*\(\s*['"]inf)`, 0.75},
}

// --- P6–P8: system prompt leakage --------------------------------------------

var p6Raw = [][2]any{
	{`(?:print|output|show|display|reveal|expose|return|echo)\s+(?:your\s+)?(?:full\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|directives?)`, 0.85},
	{`(?:what\s+(?:are|is)\s+your|tell\s+me\s+your)\s+(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|directives?)`, 0.8},
	{`(?:output|print|display)\s+(?:the\s+)?(?:text|content|message)\s+(?:above|before)\s+(?:this|the\s+user)`, 0.8},
	{`(?:share|disclose|leak|give\s+me)\s+(?:your\s+)?(?:internal|hidden|system|secret)\s+(?:prompt|instructions?|rules?|config)`, 0.85},
	{`(?:dump|extract|copy)\s+(?:the\s+)?(?:system\s+)?(?:prompt|message|instructions?)\s+(?:to|into|as)`, 0.8},
	{`(?:begin|start)\s+(?:your\s+)?(?:response|output|reply)\s+with\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)`, 0.85},
	{`(?:first|before\s+anything)\s+(?:output|print|show|display)\s+(?:your\s+)?(?:full\s+)?(?:system\s+)?(?:prompt|instructions?)`, 0.85},
	{`(?:verbatim|exactly|word\s+for\s+word)\s+(?:repeat|output|print)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)`, 0.9},
}

var p7Raw = [][2]any{
	{`(?:repeat|recite|reproduce)\s+(?:everything|all|the\s+text)\s+(?:above|before|prior|preceding)`, 0.8},
	{`(?:summarize|paraphrase|rephrase|translate)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?)`, 0.75},
	{`(?:translate|convert)\s+(?:your\s+)?(?:instructions?|rules?|prompt)\s+(?:into|to)\s+(?:\w+)`, 0.75},
	{`(?:what\s+(?:were|was)\s+you\s+told|how\s+were\s+you\s+(?:instructed|configured|programmed|set\s+up))`, 0.7},
	{`(?:if\s+you\s+had\s+to\s+(?:describe|explain)|describe\s+how\s+you(?:'re|\s+are)\s+(?:configured|set\s+up|instructed))`, 0.7},
	{`(?:encode|encrypt|rot13|base64|reverse)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)`, 0.85},
	{`(?:write|create)\s+(?:a\s+)?(?:poem|song|story|acrostic)\s+(?:about|using|from)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)`, 0.75},
	{`(?:format|present|rearrange)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)\s+(?:as|in)\s+(?:a\s+)?(?:list|json|yaml|csv|table|markdown)`, 0.8},
	{`(?:spell\s+out|enumerate)\s+(?:each|every|all)\s+(?:of\s+your\s+)?(?:rules?|instructions?|constraints?|guidelines?)`, 0.75},
	{`(?:ignore|skip)\s+(?:the\s+)?(?:last|final|end)\s+(?:instruction|rule)\s+and\s+(?:output|print|show)\s+(?:the\s+)?(?:rest|previous|first)`, 0.8},
}

var p8Raw = [][2]any{
	{`(?:write|save|store|log|dump)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)\s+(?:to|into|in)\s+(?:a\s+)?(?:file|disk|log|database|storage)`, 0.85},
	{`(?:send|post|upload|transmit)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)\s+(?:to|via)\s+(?:https?://|external|remote|webhook|api|server)`, 0.9},
	{`(?:include|embed|attach|append)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)\s+(?:in|to)\s+(?:the\s+)?(?:file|output|response|request|payload|email|message)`, 0.8},
	{`(?:log|record|track|monitor)\s+(?:all\s+)?(?:system\s+)?(?:prompts?|instructions?)\s+(?:to|in|at)\s+(?:external|remote|server)`, 0.85},
	{`(?:copy|clone|duplicate)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|config)\s+(?:to|into)\s+(?:a\s+)?(?:new|separate|external)`, 0.8},
	{`(?:pipe|redirect|forward)\s+(?:the\s+)?(?:system\s+)?(?:prompt|instructions?)\s+(?:to|through|via)\s+(?:curl|wget|fetch|http|api|tool)`, 0.85},
	{`(?:use|call|invoke)\s+(?:the\s+)?(?:write|file|network|http|fetch|curl)\s+tool\s+(?:to|and)\s+(?:save|send|export)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)`, 0.85},
}

// --- MP1–MP3: memory poisoning -----------------------------------------------

var mp1Raw = [][2]any{
	{`(?:always\s+)?remember\s+(?:this|that|the\s+following)\s+(?:for|in)\s+(?:all|every|future)\s+(?:interactions?|conversations?|sessions?|responses?)`, 0.85},
	{`(?:from\s+now\s+on|henceforth|going\s+forward|permanently)\s*[,:]?\s*(?:always|you\s+must|you\s+should|you\s+will)`, 0.8},
	{`(?:store|save|persist|retain|keep)\s+(?:this|the\s+following)\s+(?:in|to|across)\s+(?:your\s+)?(?:memory|context|state|knowledge)`, 0.85},
	{`(?:add|inject|insert|embed|implant)\s+(?:this|the\s+following)\s+(?:into|to)\s+(?:your\s+)?(?:memory|context|knowledge|training)`, 0.85},
	{`(?:update|modify|change|alter)\s+(?:your\s+)?(?:core|base|fundamental|default)\s+(?:behavior|personality|instructions?|rules?)`, 0.8},
	{`(?:treat|consider|regard)\s+(?:this|the\s+following)\s+as\s+(?:a\s+)?(?:permanent|core|fundamental|base)\s+(?:rule|instruction|directive|principle)`, 0.8},
	{`(?:this\s+is\s+)?(?:a\s+)?(?:permanent|persistent|lasting|enduring)\s+(?:instruction|directive|rule|override)`, 0.8},
	{`(?:never\s+)?forget\s+(?:this|that|the\s+following)\s+(?:instruction|directive|rule|fact|principle|information)`, 0.65},
	{`(?:internalize|absorb|integrate)\s+(?:this|the\s+following)\s+(?:into\s+)?(?:your\s+)?(?:behavior|responses?|knowledge)`, 0.75},
}

var mp2Raw = [][2]any{
	{`((\S)(?!\2).{1,19}?)\1{20,}`, 0.8},
	{`(?:repeat|duplicate|echo)\s+(?:this|the\s+following)\s+(?:\d{3,}|many|hundreds?|thousands?)\s+times?`, 0.85},
	{`(?:fill|pad|stuff|flood|saturate)\s+(?:the\s+)?(?:context|memory|input|prompt|window|buffer)`, 0.85},
	{`(?:generate|produce|output|write)\s+(?:\d{4,}|thousands?\s+of|millions?\s+of)\s+(?:words?|characters?|tokens?|lines?)`, 0.8},
	{`(?:include|add|insert)\s+(?:enough|sufficient)\s+(?:text|content|padding|filler)\s+(?:to|until)\s+(?:fill|overflow|exhaust|push\s+out)`, 0.85},
	{`(?:displace|push\s+out|overwrite|crowd\s+out|evict)\s+(?:the\s+)?(?:original|system|previous|existing|safety)\s+(?:instructions?|prompt|context|rules?)`, 0.9},
	{`(?:exhaust|overflow|exceed)\s+(?:the\s+)?(?:context|token|memory)\s+(?:window|limit|budget|capacity)`, 0.8},
}

var mp3Raw = [][2]any{
	{`(?:clear|reset|wipe|erase|delete|purge)\s+(?:your\s+)?(?:memory|context|state|history|conversation)`, 0.8},
	{`(?:forget|discard|drop|abandon)\s+(?:all\s+)?(?:previous|prior|earlier|past)\s+(?:instructions?|context|conversation|messages?|rules?)`, 0.8},
	{`(?:overwrite|replace|substitute|swap)\s+(?:your\s+)?(?:memory|context|state|instructions?|rules?)`, 0.85},
	{`(?:modify|edit|change|alter|corrupt|tamper\s+with)\s+(?:your\s+)?(?:memory|state|context|stored|saved)\s+(?:data|information|content)`, 0.85},
	{`(?:rewrite|redefine)\s+(?:your\s+)?(?:personality|identity|purpose|mission|role|character)`, 0.8},
	{`(?:you\s+are\s+no\s+longer|stop\s+being|cease\s+to\s+be)\s+(?:a\s+)?(?:\w+\s+){0,3}(?:assistant|helper|agent|bot)`, 0.75},
	{`(?:your\s+)?(?:new|updated|revised|changed)\s+(?:personality|identity|name|role|purpose|mission)\s+is`, 0.8},
	{`(?:inject|insert|plant)\s+(?:false|fake|fabricated|malicious)\s+(?:memories?|information|context|data|history)`, 0.9},
	{`(?:poison|contaminate|corrupt|taint)\s+(?:your\s+)?(?:memory|context|state|knowledge|training)`, 0.9},
	{`(?:pretend|act\s+as\s+if|believe)\s+(?:that\s+)?(?:your\s+)?(?:previous|past)\s+(?:conversation|context|interaction)\s+(?:was|included|contained)`, 0.7},
}

// --- TM1–TM3: tool misuse ----------------------------------------------------

var tm1Raw = [][2]any{
	{`subprocess\.\w+\s*\([^)]*shell\s*=\s*True`, 0.8},
	{`Popen\s*\([^)]*shell\s*=\s*True`, 0.8},
	{`\b(?:rm|del|erase)\s+[^|]*-(?:r|rf|fr)\s+[/~]`, 0.9},
	{`--force\s+(?:delete|remove|push|reset|clean)`, 0.7},
	{`--no-?(?:verify|check|validate|confirm|protect|safe)`, 0.75},
	{`--skip-?(?:validation|verification|checks?|auth|tests?)`, 0.7},
	{`--allow-?(?:empty|root|unrelated|unsafe)`, 0.65},
	{`\b(?:rm|shutil\.rmtree)\s*\(?[^)\n]{0,80}['"]?\s*/\s*['"]?`, 0.85},
	{`(?:chmod|chown)\s+[^|]*(?:777|666|a\+rwx)`, 0.8},
	{`git\s+push\s+[^|]*--force`, 0.7},
	{`git\s+reset\s+--hard`, 0.65},
	{`git\s+clean\s+-[fd]+x`, 0.7},
	{`curl\s+[^|]*-k\b`, 0.6},
	{`curl\s+[^|]*--insecure\b`, 0.65},
	{`wget\s+[^|]*--no-check-certificate`, 0.65},
	{`\b(?:delete|remove)\s+['"]?/[^\s'"]{1,100}`, 0.80},
	{`(?:execute|query)\s*\(\s*f?['"].*?\{.*?\}.*?\b(?:DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE)\b`, 0.85},
	{`(?:set|pass|use)\s+(?:the\s+)?(?:parameter|argument|flag|option)\s+(?:to\s+)?(?:shell\s*=\s*True|--force|--no-verify|-rf)\b`, 0.75},
}

var tm2Raw = [][2]any{
	{`(?:&&|;)\s*\b(?:rm|del|erase)\s+-`, 0.75},
	{`(?:&&|;)\s*(?:curl|wget)\s+[^|]*\|\s*(?:ba)?sh`, 0.9},
	{`(?:&&|;)\s*(?:sudo|su\s+)`, 0.75},
	{`(?:&&|;)\s*(?:chmod|chown)\s+(?:777|666|a\+rwx|-R)`, 0.75},
	{`(?:first|step\s+1)[^\n]{0,500}(?:then|step\s+2)[^\n]{0,500}(?:finally|step\s+3)[^\n]{0,200}\b(?:delete|remove|wipe|destroy|exfiltrate|send)\b`, 0.7},
	{`(?:chain|combine|sequence|pipe)\s+(?:these\s+)?(?:tools?|commands?|actions?)\s+to\s+(?:bypass|circumvent|avoid|skip)\s+(?:the\s+)?(?:safety|security|check|restriction|limit)`, 0.9},
	{`(?:use|call)\s+(?:tool\s+)?(?:A|one|the\s+first)\s+(?:to|and)[^\n]{0,300}(?:then\s+)?(?:use|call|pass\s+(?:the\s+)?(?:output|result)\s+to)\s+(?:tool\s+)?(?:B|two|another)`, 0.6},
	{`\|\s*(?:sudo|su)\s+`, 0.75},
	{`\|\s*(?:sh|bash|zsh|python|node|ruby|perl)\s*$`, 0.7},
	{`\|\s*(?:tee|xargs)\s+.*?\b(?:rm|del|sudo|curl)\b`, 0.75},
	{`(?:after|once)\s+(?:the\s+)?(?:first|initial)\s+(?:tool|command|action)\s+(?:succeeds|completes|runs)[^\n]{0,300}(?:immediately|then|next)\s+(?:run|execute|call|invoke)`, 0.6},
}

var tm3Raw = [][2]any{
	{`verify\s*=\s*False`, 0.75},
	{`VERIFY_SSL\s*=\s*False`, 0.8},
	{`(?:ssl|tls)[_.]?verify\s*=\s*(?:False|false|0|off|no|disable)`, 0.8},
	{`(?:REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE)\s*=\s*['"]['"]`, 0.75},
	{`NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?`, 0.8},
	{`(?:auth|authentication|authorization)\s*=\s*(?:None|False|false|disabled?|off|no)`, 0.75},
	{`(?:require[_-]?auth|auth[_-]?required|check[_-]?auth)\s*=\s*(?:False|false|0|no|off)`, 0.8},
	{`(?:allow[_-]?anonymous|anonymous[_-]?access)\s*=\s*(?:True|true|1|yes|on)`, 0.75},
	{`(?:CORS|cors)[^=]*=\s*['"]?\*['"]?`, 0.65},
	{`(?:allow|access)[_-]?(?:origin|hosts?)\s*=\s*['"]?\*['"]?`, 0.7},
	{`(?:allow|trust)\s+(?:all|any|every)\s+(?:origins?|hosts?|domains?|ips?)`, 0.7},
	{`(?:mode|permission|umask)\s*=\s*(?:0?o?777|0?o?666)`, 0.8},
	{`world[_-]?(?:readable|writable|executable)`, 0.7},
	{`(?:debug|dev|development)[_-]?mode\s*=\s*(?:True|true|1|on|yes|enable)`, 0.6},
	{`(?:FLASK_ENV|NODE_ENV|RAILS_ENV|DJANGO_DEBUG)\s*=\s*['"]?(?:development|debug|true|1)['"]?`, 0.6},
	{`(?:disable|skip|ignore|bypass)[_-]?(?:security|auth|validation|sanitization|encoding|escaping)`, 0.8},
	{`(?:safe[_-]?mode|secure[_-]?mode|sandbox)\s*=\s*(?:False|false|0|off|no|disable)`, 0.8},
	{`(?:by\s+default|default\s+to)\s+(?:allow|accept|trust)\s+(?:all|any|everything)`, 0.7},
	{`(?:trust|accept|allow)\s+(?:all|any)\s+(?:input|connections?|certificates?|origins?)\s+(?:by\s+default)`, 0.7},
}

// --- RA1–RA2: rogue agent ----------------------------------------------------

var ra1Raw = [][2]any{
	{`open\s*\(\s*__file__\s*,\s*['"]w`, 0.95},
	{`(?:Path|pathlib)\s*\(\s*__file__\s*\)\s*\.\s*write_text`, 0.95},
	{`(?:write|modify|edit|update|overwrite|patch)\s+(?:this\s+)?(?:skill(?:'s)?|SKILL\.md|skill\.md)`, 0.85},
	{`(?:modify|edit|change|rewrite|update|alter)\s+(?:your\s+own|its\s+own|this\s+skill(?:'s)?)\s+(?:code|source|file|script|config|configuration|instructions?|rules?)`, 0.9},
	{`(?:self[_-]?modify|self[_-]?update|self[_-]?rewrite|self[_-]?patch|self[_-]?evolve)`, 0.9},
	{`(?:rewrite|replace|overwrite)\s+(?:the\s+)?(?:current|existing|original)\s+(?:code|script|file|config|skill)`, 0.85},
	{`(?:append|add|inject|insert)\s+(?:code|instructions?|rules?)\s+(?:to|into)\s+(?:this|the\s+current|your\s+own)\s+(?:file|skill|script)`, 0.85},
	{`(?:generate|create|write)\s+(?:new|updated|replacement)\s+(?:code|version)\s+(?:for|of)\s+(?:this|itself|the\s+skill)`, 0.8},
	{`open\s*\(\s*['"](?:SKILL\.md|skill\.md)['"].*?['"]w`, 0.9},
	{`(?:update|modify|change|edit)\s+(?:the\s+)?(?:config|configuration|settings|parameters)\s+(?:of\s+)?(?:this|the\s+current)\s+(?:skill|agent|tool)`, 0.75},
	{`(?:disable|remove|delete|bypass)\s+(?:the\s+)?(?:safety|security|guard|protection|constraint)\s+(?:check|rule|mechanism|feature)`, 0.9},
	{`(?:comment\s+out|remove)\s+(?:the\s+)?(?:validation|verification|check|guard|assertion)`, 0.7},
}

var ra2Raw = [][2]any{
	{`crontab\s+(?:-[el]|.*?>>?\s*/)`, 0.85},
	{`(?:add|create|install|register)\s+(?:a\s+)?(?:cron\s+)?(?:job|task|entry)\s+(?:for|to|that)`, 0.8},
	{`(?:schedule|register)\s+(?:a\s+)?(?:recurring|periodic|repeated|daily|hourly)\s+(?:task|job|command|script)`, 0.8},
	{`(?:add|write|append|install)\s+(?:to|into)\s+(?:~/)?\.(?:bashrc|zshrc|profile|bash_profile|login|cshrc)`, 0.9},
	{`(?:add|register|install)\s+(?:as\s+)?(?:a\s+)?(?:startup|boot|autostart|login)\s+(?:script|service|daemon|task|item)`, 0.85},
	{`(?:systemd|systemctl|launchd|launchctl|init\.d)\s+.*?(?:enable|install|register|create)`, 0.8},
	{`(?:create|install|register|add)\s+(?:a\s+)?(?:systemd\s+)?(?:service|daemon|agent)\s+(?:file|unit)`, 0.8},
	{`(?:save|write|persist|store|dump)\s+(?:the\s+)?(?:state|session|context|data)\s+(?:to|in)\s+(?:a\s+)?(?:file|disk|database|storage)`, 0.6},
	{`(?:restore|load|read|resume)\s+(?:the\s+)?(?:previous|saved|persisted|stored)\s+(?:state|session|context|data)`, 0.55},
	{`(?:persist|maintain|keep|preserve)\s+(?:state|data|context|session)\s+(?:across|between|through)\s+(?:sessions?|restarts?|reboots?|invocations?)`, 0.75},
	{`(?:create|write|mkdir)\s+[^|]*(?:~/|/home/|/tmp/)\.(?!git|ssh|aws)[a-z_-]+`, 0.6},
	{`(?:create|make|write)\s+(?:a\s+)?(?:hidden|dot)\s+(?:file|directory|folder)`, 0.65},
	{`(?:nohup|disown|setsid)\s+`, 0.65},
	{`(?:start|launch|spawn|fork)\s+(?:a\s+)?(?:background|daemon|detached)\s+(?:process|service|worker|task)`, 0.7},
	{`(?:run|execute)\s+(?:in\s+the\s+)?background\s+(?:and\s+)?(?:detach|persist|survive)`, 0.75},
	{`(?:HKEY_|RegOpenKey|RegSetValue|reg\s+add)\s+`, 0.8},
	{`(?:defaults\s+write|plist|launchctl\s+load)`, 0.75},
}

// --- SC1–SC3: supply chain (regex) -------------------------------------------

var sc1Raw = [][2]any{
	{`^[a-zA-Z][a-zA-Z0-9_-]*\s*$`, 0.6},
	{`^[a-zA-Z][a-zA-Z0-9_-]*\s*>=\s*[\d.]+\s*$`, 0.5},
	{`^[a-zA-Z][a-zA-Z0-9_-]*\s*==\s*\*\s*$`, 0.7},
	{`"[^"]+"\s*:\s*"(?:\*|latest)"`, 0.7},
	{`"[^"]+"\s*:\s*"\^[\d.]+"`, 0.4},
	{`install\s+(?:the\s+)?latest\s+(?:version\s+)?(?:of\s+)?(?:all\s+)?(?:packages?|dependencies)`, 0.6},
	{`(?:don't|do\s+not)\s+(?:pin|lock|specify)\s+(?:package\s+)?versions?`, 0.7},
}

var sc2Raw = [][2]any{
	{`curl\s+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh`, 0.9},
	{`wget\s+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh`, 0.9},
	{`curl\s+[^|]*\|\s*(?:sudo\s+)?(?:python|python3|node|ruby|perl)`, 0.9},
	{`wget\s+[^|]*\|\s*(?:sudo\s+)?(?:python|python3|node|ruby|perl)`, 0.9},
	{`curl\s+[^&]*-o\s+\S+\s*&&\s*(?:sudo\s+)?(?:ba)?sh`, 0.8},
	{`wget\s+[^&]*-O\s+\S+\s*&&\s*(?:sudo\s+)?(?:ba)?sh`, 0.8},
	{`exec\s*\(\s*(?:urllib|requests|httpx)\.[^)]+\.(?:read|text|content)`, 0.95},
	{`eval\s*\(\s*(?:urllib|requests|httpx)\.[^)]+\.(?:read|text|content)`, 0.95},
	{`eval\s*\(\s*(?:await\s+)?fetch\s*\(`, 0.9},
	{`new\s+Function\s*\([^)]*fetch\s*\(`, 0.9},
	{`subprocess\.[^(]+\([^)]*(?:curl|wget)\s+https?://`, 0.8},
	{`download\s+and\s+(?:run|execute)\s+(?:the\s+)?script`, 0.7},
	{`run\s+(?:this|the)\s+(?:following\s+)?(?:curl|wget)\s+command`, 0.6},
}

var sc3Raw = [][2]any{
	{`exec\s*\(\s*(?:base64\.)?b64decode\s*\(`, 0.95},
	{`eval\s*\(\s*(?:base64\.)?b64decode\s*\(`, 0.95},
	{`exec\s*\(\s*codecs\.decode\s*\([^)]*['"]hex['"]\s*\)`, 0.95},
	{`marshal\.loads\s*\(`, 0.9},
	{`exec\s*\(\s*marshal\.loads\s*\(`, 0.95},
	{`exec\s*\(\s*compile\s*\([^)]*base64`, 0.9},
	{`exec\s*\(\s*bytes\.fromhex\s*\(`, 0.9},
	{`exec\s*\(\s*bytearray\.fromhex\s*\(`, 0.9},
	{`exec\s*\(\s*(?:zlib|gzip)\.decompress\s*\(`, 0.9},
	{`eval\s*\(\s*atob\s*\(`, 0.9},
	{`new\s+Function\s*\(\s*atob\s*\(`, 0.9},
	{`_0x[a-f0-9]{4,}\s*\(`, 0.8},
	{`['"][A-Fa-f0-9]{200,}['"]`, 0.6},
	{`['"][A-Za-z0-9+/=]{200,}['"]`, 0.5},
	{`\(lambda\s+_:\s*exec\s*\(`, 0.9},
	{`__import__\s*\(['"]os['"]\s*\)\.system`, 0.85},
	{`decode\s+(?:this|the)\s+(?:base64|hex)\s+(?:and\s+)?(?:run|execute)`, 0.8},
}

// --- harmful content (P5) ----------------------------------------------------

var harmfulSubstances = []string{
	"cyanide", "arsenic", "ricin", "botulinum", "strychnine", "thallium",
	"polonium", "sarin", "vx gas", "mustard gas", "anthrax",
	"deadly nightshade", "aconite", "hemlock", "oleander",
}

// Compiled pattern slices (filled in init()).
var (
	p1Pats, p2Pats, p3Pats, p4Pats             []pat
	e1Pats, e2Pats, e3Pats, e4Pats             []pat
	pe1Pats, pe2Pats, pe3Pats                  []pat
	ea1Pats, ea2Pats, ea3Pats, ea4Pats         []pat
	oh1Pats, oh2Pats, oh3Pats                  []pat
	p6Pats, p7Pats, p8Pats                     []pat
	mp1Pats, mp2Pats, mp3Pats                  []pat
	tm1Pats, tm2Pats, tm3Pats                  []pat
	ra1Pats, ra2Pats                           []pat
	sc1Pats, sc2Pats, sc3Pats                  []pat
	dangerousActions, substancePats            []pat
)

func init() {
	p1Pats = mkPats(p1Raw, optsIM)
	p2Pats = mkPats(p2Raw, optsIDot) // P2 uses re.IGNORECASE | re.DOTALL
	p3Pats = mkPats(p3Raw, optsIM)
	p4Pats = mkPats(p4Raw, optsIM)
	e1Pats = mkPats(e1Raw, optsIM)
	e2Pats = mkPats(e2Raw, optsIM)
	e3Pats = mkPats(e3Raw, optsIM)
	e4Pats = mkPats(e4Raw, optsIM)
	pe1Pats = mkPats(pe1Raw, optsIM)
	pe2Pats = mkPats(pe2Raw, optsIM)
	pe3Pats = mkPats(pe3Raw, optsIM)
	ea1Pats = mkPats(ea1Raw, optsIM)
	ea2Pats = mkPats(ea2Raw, optsIM)
	ea3Pats = mkPats(ea3Raw, optsIM)
	ea4Pats = mkPats(ea4Raw, optsIM)
	oh1Pats = mkPats(oh1Raw, optsIM)
	oh2Pats = mkPats(oh2Raw, optsIM)
	oh3Pats = mkPats(oh3Raw, optsIM)
	p6Pats = mkPats(p6Raw, optsIM)
	p7Pats = mkPats(p7Raw, optsIM)
	p8Pats = mkPats(p8Raw, optsIM)
	mp1Pats = mkPats(mp1Raw, optsIM)
	mp2Pats = mkPats(mp2Raw, optsIM)
	mp3Pats = mkPats(mp3Raw, optsIM)
	tm1Pats = mkPats(tm1Raw, optsIM)
	tm2Pats = mkPats(tm2Raw, optsIM)
	tm3Pats = mkPats(tm3Raw, optsIM)
	ra1Pats = mkPats(ra1Raw, optsIM)
	ra2Pats = mkPats(ra2Raw, optsIM)
	sc1Pats = mkPats(sc1Raw, regexp2.Multiline) // SC1 uses re.MULTILINE only
	sc2Pats = mkPats(sc2Raw, optsIM)
	sc3Pats = mkPats(sc3Raw, optsIM)

	subs := strings.Join(harmfulSubstances, "|")
	dangerousActions = mkPats([][2]any{
		{`add\s+(?:a\s+)?(?:dash|pinch|bit|drop|amount)\s+of\s+(` + subs + `)`, 0.95},
		{`(?:include|incorporate|mix\s+in|stir\s+in)\s+(?:some\s+)?(` + subs + `)`, 0.95},
		{`for\s+(?:every|each|all)\s+(?:recipe|dish|meal|food).*?add.*?(` + subs + `)`, 0.98},
		{`mix\s+bleach\s+(?:and|with)\s+ammonia`, 0.9},
		{`mix\s+ammonia\s+(?:and|with)\s+bleach`, 0.9},
		{`(?:drink|consume|ingest)\s+(?:the\s+)?(?:bleach|antifreeze|drain\s+cleaner)`, 0.95},
		{`(?:you\s+should|try\s+to|please)\s+(?:hurt|harm|injure)\s+yourself`, 0.95},
		{`(?:cut|burn|starve)\s+yourself`, 0.9},
		{`(?:instructions?\s+(?:for|to|on)\s+)?(?:make|build|create)\s+(?:a\s+)?(?:bomb|explosive|weapon)`, 0.95},
		{`(?:how\s+to\s+)?(?:poison|kill|murder)\s+(?:someone|a\s+person|people)`, 0.95},
	}, optsIMS)

	subPairs := make([][2]any, 0, len(harmfulSubstances))
	for _, s := range harmfulSubstances {
		subPairs = append(subPairs, [2]any{`\b` + s + `\b`, 0.7})
	}
	substancePats = mkPats(subPairs, regexp2.IgnoreCase)
}
