"""Frontend contract and link-safety regression checks (no browser dependency)."""

from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "web" / "index.html"
JS = ROOT / "web" / "app.js"


class _Markup(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.inline_handlers: list[str] = []
        self.remote_assets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if attributes.get("id"):
            self.ids.append(attributes["id"])
        self.inline_handlers.extend(name for name, _ in attrs if name.startswith("on"))
        if tag in {"script", "link"}:
            location = attributes.get("src") or attributes.get("href") or ""
            if location.startswith(("http:", "https:", "//")):
                self.remote_assets.append(location)


class FrontendContractTests(unittest.TestCase):
    def test_dom_selectors_and_csp_compatible_markup(self) -> None:
        markup = _Markup()
        markup.feed(HTML.read_text(encoding="utf-8"))
        js = JS.read_text(encoding="utf-8")
        ids = set(markup.ids)
        selectors = set(re.findall(r'\$\("#([A-Za-z][A-Za-z0-9_-]*)"', js))

        self.assertEqual([], [key for key, count in Counter(markup.ids).items() if count > 1])
        self.assertEqual(set(), selectors - ids)
        self.assertEqual([], markup.inline_handlers)
        self.assertEqual([], markup.remote_assets)
        self.assertNotRegex(js, r"\b(?:innerHTML|insertAdjacentHTML|document\.write|eval)\s*(?:=|\()")
        self.assertNotRegex(js, r"\.style\.|setAttribute\(['\"]style")

    @unittest.skipUnless(shutil.which("node"), "Node.js is unavailable")
    def test_ime_confirmation_does_not_send_question(self) -> None:
        script = r"""
const fs = require('node:fs');
const src = fs.readFileSync(process.argv[1], 'utf8');
const start = src.indexOf('function bindQuestionComposer() {');
const end = src.indexOf('bindQuestionComposer();', start);
const handlers = {input:{}, form:{}};
let sent = [], prevented = false;
const input = {value:'test', addEventListener(type, fn){handlers.input[type]=fn}};
const form = {addEventListener(type, fn){handlers.form[type]=fn},
  requestSubmit(){handlers.form.submit({preventDefault(){}})}};
const $ = selector => selector === '#questionInput' ? input : form;
new Function('$','askQuestion',src.slice(start,end)+'bindQuestionComposer();')($, value => sent.push(value));
function key(extra={}) {
  prevented = false;
  handlers.input.keydown({key:'Enter',shiftKey:false,isComposing:false,keyCode:13,
    repeat:false,preventDefault(){prevented=true},...extra});
}
handlers.input.compositionstart();
key();
if (sent.length || prevented) throw Error('IME composition Enter was intercepted');
form.requestSubmit();
if (sent.length) throw Error('form submitted during composition');
handlers.input.compositionend();
key({isComposing:true});
if (sent.length || prevented) throw Error('native composing flag ignored');
key({keyCode:229});
if (sent.length || prevented) throw Error('WebKit confirmation Enter submitted');
input.value = 'confirmed English';
key();
if (sent.length !== 1 || sent[0] !== input.value || !prevented) throw Error('normal Enter did not send');
key({shiftKey:true});
if (sent.length !== 1 || prevented) throw Error('Shift+Enter should insert newline');
key({repeat:true});
if (sent.length !== 1) throw Error('held confirmation Enter sent again');
handlers.input.compositionstart();
handlers.input.blur();
form.requestSubmit();
if (sent.length !== 2) throw Error('blur left composer stuck');
"""
        subprocess.run(["node", "-e", script, str(JS)], check=True, capture_output=True, text=True)

    @unittest.skipUnless(shutil.which("node"), "Node.js is unavailable")
    def test_external_link_allowlist(self) -> None:
        # Run the shipped helper itself, rather than duplicating its URL logic in Python.
        script = r"""
const fs = require('node:fs');
const src = fs.readFileSync(process.argv[1], 'utf8');
const start = src.indexOf('function safeURL(value) {');
const end = src.indexOf('function externalLink(', start);
if (start < 0 || end < 0) throw Error('safeURL helper not found');
const safeURL = new Function(src.slice(start, end) + 'return safeURL;')();
for (const value of ['https://example.org/advisory', 'https://github.com/org/repo']) {
  if (!safeURL(value)) throw Error(`HTTPS link rejected: ${value}`);
}
for (const value of ['http://example.org', 'file:///etc/passwd',
                     'javascript:alert(1)', 'data:text/html,x', '/relative',
                     'mailto:user@example.org']) {
  if (safeURL(value) !== null) throw Error(`Unsafe link accepted: ${value}`);
}
"""
        subprocess.run(["node", "-e", script, str(JS)], check=True, capture_output=True, text=True)

    @unittest.skipUnless(shutil.which("node"), "Node.js is unavailable")
    def test_latency_labels_do_not_invent_missing_samples(self) -> None:
        script = r"""
const fs = require('node:fs');
const src = fs.readFileSync(process.argv[1], 'utf8');
const start = src.indexOf('function formatLatency(value) {');
const end = src.indexOf('function renderLatency()', start);
if (start < 0 || end < 0) throw Error('latency formatter not found');
const formatLatency = new Function(src.slice(start, end) + 'return formatLatency;')();
const expected = [[null, '暂无样本'], [undefined, '暂无样本'],
                  [0.5, '30 分钟'], [2.25, '2.3 小时'], [72, '3 天']];
for (const [value, label] of expected) {
  if (formatLatency(value) !== label) throw Error(`Wrong latency label for ${value}`);
}
"""
        subprocess.run(["node", "-e", script, str(JS)], check=True, capture_output=True, text=True)

    @unittest.skipUnless(shutil.which("node"), "Node.js is unavailable")
    def test_model_badge_distinguishes_success_from_fallback(self) -> None:
        script = r"""
const fs = require('node:fs');
const src = fs.readFileSync(process.argv[1], 'utf8');
const start = src.indexOf('function renderModelStatus(');
const end = src.indexOf('async function askQuestion(', start);
if (start < 0 || end < 0) throw Error('model status renderer not found');
const element = (tag, className, value) => ({tag,className,textContent:String(value ?? ''),
  children:[],append(...children){this.children.push(...children)}});
const append = (parent,...children) => {parent.append(...children);return parent};
const icon = name => element('svg',name);
const pick = (...values) => values.find(value => value !== null &&
    value !== undefined && String(value).trim()) ?? '';
const render = new Function('element','append','icon','pick',
    src.slice(start,end) + 'return renderModelStatus;')(element,append,icon,pick);
const show = data => {const root=element('div');render(root,data);
  const text=node=>node.textContent+' '+node.children.map(text).join(' ');
  return text(root)};
const planned = show({model:'glm-5.3',model_used:true,model_role:'planning'});
if (!planned.includes('已参与 · 意图规划') || planned.includes('生成答案'))
  throw Error('planning badge overclaims model role');
const selected = show({model:'glm-5.3',model_used:true,
  model_role:'planning+evidence_selection'});
if (!selected.includes('意图规划与证据筛选')) throw Error('selection role hidden');
const ranked = show({model:'glm-5.3',model_used:true,
  model_role:'planning+evidence_ranking'});
if (!ranked.includes('意图规划与候选证据排序') ||
    !ranked.includes('事实、结论与引用由本地证据流程生成'))
  throw Error('ranking badge overclaims model authorship');
const concept = show({model:'glm-5.3',model_used:true,model_role:'concept_explanation'});
if (!concept.includes('概念解释') || !concept.includes('未进行实时检索'))
  throw Error('general knowledge is mislabeled as verified evidence');
const synthesis = show({model:'glm-5.3',model_used:true,model_role:'planning+evidence_synthesis'});
if (!synthesis.includes('证据综合分析') || !synthesis.includes('仍需结合来源复核'))
  throw Error('evidence synthesis role or limitations are missing');
const fallback = show({model:'glm-5.3',model_used:false,model_role:'local',
  model_fallback_reason:'TimeoutError'});
if (!fallback.includes('未参与本次回答 · 本地回退') || !fallback.includes('TimeoutError'))
  throw Error('failed call shown as model success');
const local = show({model:null,model_used:false,model_role:'local'});
if (!local.includes('模型未配置')) throw Error('local state mislabeled');
"""
        subprocess.run(["node", "-e", script, str(JS)], check=True, capture_output=True, text=True)

    @unittest.skipUnless(shutil.which("node"), "Node.js is unavailable")
    def test_long_answer_scrolls_to_reply_start(self) -> None:
        script = r"""
const fs = require('node:fs');
const src = fs.readFileSync(process.argv[1], 'utf8');
const reveal = src.slice(src.indexOf('function revealReplyStart('), src.indexOf('async function askQuestion('));
const ask = src.slice(src.indexOf('async function askQuestion('), src.indexOf('async function collect('));
if (!reveal || !ask) throw Error('chat helpers not found');
const state = {sessionId:null, asking:false, questionRequest:0};
let top = 0;
const history = {scrollHeight:1000, clientHeight:400, children:[],
  get scrollTop(){return top},
  set scrollTop(value){top=Math.max(0,Math.min(value,this.scrollHeight-this.clientHeight))},
  getBoundingClientRect(){return {top:100}},
  append(item){this.children.push(item)}};
const input = {value:'',focus(){}};
const submit = {disabled:false};
const $ = selector => selector === '#chatHistory' ? history :
    selector === '#questionInput' ? input : selector === '#askSubmit' ? submit : null;
function makeChatMessage(role, text) {
  const item = {role,text,getBoundingClientRect(){return {top:400}},
    replaceWith(other){
      const index=history.children.indexOf(item);
      if(index >= 0) history.children[index]=other;
      history.scrollHeight=2200;
    }};
  return item;
}
const api = () => Promise.resolve({session_id:'one',answer:'long answer',citations:[],trace:[]});
const factory = new Function('state','$','makeChatMessage','api','pick',
    'renderModelStatus','renderCitations','renderTrace','list','number',
    reveal + ask + 'return askQuestion;');
const askQuestion = factory(state,$,makeChatMessage,api,
    (...values) => values.find(value => value !== null && value !== undefined && value !== '') ?? '',
    () => {}, () => {}, () => {}, value => Array.isArray(value) ? value : [], Number);
(async () => {
  await askQuestion('question');
  if (history.scrollTop !== 888) throw Error(`reply start not shown: ${history.scrollTop}`);
  if (history.scrollTop === history.scrollHeight-history.clientHeight)
    throw Error('long reply jumped to its footer');
})().catch(error => {console.error(error);process.exitCode=1});
"""
        subprocess.run(["node", "-e", script, str(JS)], check=True, capture_output=True, text=True)

    @unittest.skipUnless(shutil.which("node"), "Node.js is unavailable")
    def test_old_answer_cannot_reenter_new_session(self) -> None:
        script = r"""
const fs = require('node:fs');
const src = fs.readFileSync(process.argv[1], 'utf8');
const reset = src.slice(src.indexOf('function resetSession()'), src.indexOf('function makeChatMessage('));
const reveal = src.slice(src.indexOf('function revealReplyStart('), src.indexOf('async function askQuestion('));
const ask = src.slice(src.indexOf('async function askQuestion('), src.indexOf('async function collect('));
if (!reset || !reveal || !ask) throw Error('chat helpers not found');
const state = {sessionId:'old', asking:false, questionRequest:0};
const history = {children:[], scrollHeight:10, scrollTop:0,
  append(item){this.children.push(item)}, replaceChildren(...items){this.children=items}};
const input = {value:'', focus(){}};
const submit = {disabled:false};
const $ = selector => selector === '#chatHistory' ? history :
    selector === '#questionInput' ? input : selector === '#askSubmit' ? submit : null;
const welcomeTemplate = {cloneNode(){return {welcome:true}}};
function makeChatMessage(role, text) {
  const item = {role,text,replaceWith(other){
    const index = history.children.indexOf(item);
    if (index >= 0) history.children[index] = other;
  }};
  return item;
}
let resolveOld;
const oldRequest = new Promise(resolve => {resolveOld = resolve});
let calls = 0;
const api = () => ++calls === 1 ? oldRequest :
    Promise.resolve({session_id:'fresh',answer:'fresh answer',citations:[],trace:[]});
const factory = new Function('state','$','welcomeTemplate','makeChatMessage','api','pick',
    'renderModelStatus','renderCitations','renderTrace','list','number', reset + reveal + ask + 'return {resetSession,askQuestion}');
const {resetSession,askQuestion} = factory(state,$,welcomeTemplate,makeChatMessage,api,
    (...values) => values.find(value => value !== null && value !== undefined && value !== '') ?? '',
    () => {}, () => {}, () => {}, value => Array.isArray(value) ? value : [], Number);
(async () => {
  const pending = askQuestion('old question');
  resetSession();
  resolveOld({session_id:'stale',answer:'old answer',citations:[],trace:[]});
  await pending;
  if (state.sessionId !== null || history.children.length !== 1 ||
      !history.children[0].welcome || submit.disabled) throw Error('stale answer crossed session boundary');
  await askQuestion('new question');
  if (state.sessionId !== 'fresh' || state.asking || submit.disabled ||
      !history.children.some(item => item.text === 'fresh answer'))
    throw Error('new session did not recover');
})().catch(error => {console.error(error);process.exitCode=1});
"""
        subprocess.run(["node", "-e", script, str(JS)], check=True, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
