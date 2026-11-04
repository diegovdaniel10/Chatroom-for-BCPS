import subprocess, time, sys, os, tempfile
from playwright.sync_api import sync_playwright
env=dict(os.environ, PORT="3111", OWNER_CLAIM_CODE="e2e-owner-code", DATABASE_URL="sqlite:///"+tempfile.mkdtemp()+"/e2e.db")
srv=subprocess.Popen([sys.executable,"backend/server.py"],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
time.sleep(1.5)
errs=[]
try:
    with sync_playwright() as p:
        b=p.chromium.launch()
        def mk():
            ctx=b.new_context(viewport={"width":1280,"height":800}); pg=ctx.new_page()
            pg.on("console",lambda m: errs.append(m.text) if m.type=="error" else None)
            pg.on("pageerror",lambda e: errs.append(str(e))); return pg
        o=mk(); o.goto("http://127.0.0.1:3111/")
        o.fill("#login-name","Dana K"); o.click("summary"); o.fill("#login-code","e2e-owner-code"); o.click("#login-form button[type=submit]")
        o.wait_for_selector(".chan"); 
        s=mk(); s.goto("http://127.0.0.1:3111/"); s.fill("#login-name","Sam Student"); s.click("#login-form button[type=submit]"); s.wait_for_selector(".chan")
        s.fill("#msg-input","hello from sam <b>x</b>"); s.press("#msg-input","Enter")
        o.wait_for_selector(".msg .text:has-text('hello from sam')", timeout=5000)
        print("realtime ok; live dot:", o.get_attribute("#conn-state","class"))
        assert o.inner_html(".msg .text").count("<b>")==0
        o.screenshot(path="/tmp/desktop.png")
        s.set_viewport_size({"width":390,"height":780}); s.screenshot(path="/tmp/mobile.png")
        # owner promotes sam via profile modal
        o.click(".member:has-text('Sam Student')"); o.select_option("#modal select >> nth=0","moderator"); o.click("text=Set role")
        s.wait_for_selector("#me-role:has-text('Moderator')",timeout=5000)
        print("role update pushed live: ok")
        b.close()
finally:
    srv.terminate()
print("console errors:",errs)
