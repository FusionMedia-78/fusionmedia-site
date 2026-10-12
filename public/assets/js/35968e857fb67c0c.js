// Fusion Media. v5. Vanilla JS only. Mobile first. Motion explains or rewards; it never blocks content.
(function () {
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var desktop = window.matchMedia('(min-width: 980px)');
  var canHover = window.matchMedia('(hover: hover)').matches;
  var hasIO = 'IntersectionObserver' in window;
  var $ = function (s, c) { return (c || document).querySelector(s); };
  var $$ = function (s, c) { return [].slice.call((c || document).querySelectorAll(s)); };
  var root = document.documentElement;

  /* ---------- Header. Tucks away going down; comes back only after a deliberate scroll up. ---------- */
  var head = $('.site-head'), nav = $('#nav'), toggle = $('.nav-toggle');
  var bar = document.createElement('div'); bar.className = 'progress'; bar.setAttribute('aria-hidden', 'true'); document.body.appendChild(bar);
  var lastY = window.scrollY, upFrom = lastY, ticking = false;
  function typing() { var a = document.activeElement; return a && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName); }
  function frame() {
    var y = window.scrollY, max = root.scrollHeight - window.innerHeight;
    head.classList.toggle('scrolled', y > 8);
    if (!nav.classList.contains('open')) {
      if (y > lastY + 2) { upFrom = y; if (y > 320) head.classList.add('tuck'); }
      else if (y < lastY - 2) { if ((upFrom - y > 80 || y < 120) && !typing()) head.classList.remove('tuck'); }
    }
    bar.style.transform = 'scaleX(' + (max > 0 ? Math.min(1, y / max) : 0) + ')';
    lastY = y; ticking = false;
  }
  window.addEventListener('scroll', function () { if (!ticking) { ticking = true; requestAnimationFrame(frame); } }, { passive: true });
  frame();
  head.addEventListener('focusin', function () { head.classList.remove('tuck'); });

  /* ---------- Phone menu: wipes open, links stagger, scrim behind ---------- */
  var scrim = document.createElement('div'); scrim.className = 'scrim'; document.body.appendChild(scrim);
  function menu(open) {
    nav.classList.toggle('open', open); scrim.classList.toggle('on', open);
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    document.body.style.overflow = open ? 'hidden' : '';
    if (open) head.classList.remove('tuck');
  }
  toggle.addEventListener('click', function () { menu(!nav.classList.contains('open')); });
  scrim.addEventListener('click', function () { menu(false); });
  nav.addEventListener('click', function (e) { if (e.target.closest('a')) menu(false); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && nav.classList.contains('open')) { menu(false); toggle.focus(); } });
  desktop.addEventListener ? desktop.addEventListener('change', function () { menu(false); }) : 0;

  /* ---------- Reveal, short stagger, one wipe per section ---------- */
  $$('[data-stagger]').forEach(function (p) { $$(':scope > *', p).forEach(function (el, i) { el.style.setProperty('--i', i % 4); }); });
  $$('.chain li').forEach(function (li, i) { li.style.setProperty('--i', i); });
  var watch = $$('.reveal, .wipe, .chain, .offers');
  if (hasIO && !reduce) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { en.target.classList.add('in'); io.unobserve(en.target); } });
    }, { rootMargin: '0px 0px -5% 0px', threshold: 0.04 });
    watch.forEach(function (el) { io.observe(el); });
    window.addEventListener('load', function () { setTimeout(function () {
      watch.forEach(function (el) { if (el.getBoundingClientRect().top < window.innerHeight) el.classList.add('in'); });
    }, 600); });
  } else { watch.forEach(function (el) { el.classList.add('in'); }); }

  /* ---------- Proof detail: collapsed on a phone, always open on desktop ---------- */
  function beats() { $$('.more-beats').forEach(function (d) { if (desktop.matches) d.open = true; else if (!d.hasAttribute('data-touched')) d.open = false; }); }
  $$('.more-beats summary').forEach(function (s) { s.addEventListener('click', function () { s.parentNode.setAttribute('data-touched', ''); }); });
  beats(); desktop.addEventListener ? desktop.addEventListener('change', beats) : 0;

  /* ---------- Rails: pager that follows the finger, one small nudge the first time ---------- */
  $$('.rail:not(.stack)').forEach(function (rail) {
    var items = $$(':scope > *', rail); if (items.length < 2) return;
    var pg = document.createElement('div'); pg.className = 'pager'; pg.setAttribute('aria-hidden', 'true');
    pg.innerHTML = '<span></span><div class="track"><i></i></div><span>Swipe</span>';
    rail.parentNode.insertBefore(pg, rail.nextSibling);
    var num = pg.firstChild, seg = $('.track i', pg); seg.style.width = (100 / items.length) + '%';
    var raf = false;
    function sync() {
      raf = false; var max = rail.scrollWidth - rail.clientWidth; if (max <= 0) return;
      var t = rail.scrollLeft / max, idx = Math.round(t * (items.length - 1));
      num.textContent = (idx + 1) + ' / ' + items.length;
      seg.style.transform = 'translateX(' + (t * (items.length - 1) * 100) + '%)';
    }
    rail.addEventListener('scroll', function () { if (!raf) { raf = true; requestAnimationFrame(sync); } }, { passive: true });
    sync(); window.addEventListener('resize', sync);
    rail.setAttribute('tabindex', '0'); rail.setAttribute('role', 'group'); rail.setAttribute('aria-label', (rail.getAttribute('data-rail') || 'items') + ', swipe sideways for more');
    if (hasIO && !reduce) {
      var once = new IntersectionObserver(function (en) {
        if (en[0].isIntersecting && rail.scrollWidth > rail.clientWidth + 8) { rail.classList.add('nudge'); once.disconnect(); }
      }, { threshold: 0.6 });
      once.observe(rail);
    }
  });

  /* ---------- Hero: the rewrite. Fixed height, pauses off screen, tap to pause, swipe to change. ---------- */
  var hero = $('.hero'); if (hero) requestAnimationFrame(function () { hero.classList.add('ready'); });
  var ba = $('.ba[data-rotate]');
  if (ba) {
    var sets = $$('.ba-set', ba), dots = $$('.ba-dots button', ba), label = $('.ba-head > span', ba);
    var cur = 0, timers = [], auto = !reduce, onScreen = true, dwell = 9000;
    sets.forEach(function (s) {
      var p = $('.ba-after p', s), words = p.textContent.trim().split(/\s+/);
      p.setAttribute('aria-label', p.textContent.trim());
      p.innerHTML = words.map(function (w, i) { return '<span class="w" aria-hidden="true" style="transition-delay:' + (i * 60) + 'ms">' + w + '</span>'; }).join(' ');
    });
    function clear() { timers.forEach(clearTimeout); timers = []; }
    function play(i, instant) {
      clear(); cur = (i + sets.length) % sets.length;
      sets.forEach(function (s, n) { s.classList.toggle('on', n === cur); s.classList.remove('struck', 'written'); s.setAttribute('aria-hidden', n === cur ? 'false' : 'true'); });
      dots.forEach(function (d, n) { d.setAttribute('aria-pressed', n === cur ? 'true' : 'false'); });
      if (label) label.textContent = sets[cur].getAttribute('data-label');
      ba.classList.remove('playing', 'paused'); void ba.offsetWidth;
      var s = sets[cur];
      if (instant || reduce) s.classList.add('struck', 'written');
      else { timers.push(setTimeout(function () { s.classList.add('struck'); }, 800)); timers.push(setTimeout(function () { s.classList.add('written'); }, 1900)); }
      if (auto && onScreen) { ba.style.setProperty('--dwell', dwell + 'ms'); ba.classList.add('playing'); timers.push(setTimeout(function () { play(cur + 1); }, dwell)); }
    }
    function stop() { auto = false; clear(); ba.classList.remove('playing'); sets[cur].classList.add('struck', 'written'); }
    dots.forEach(function (d, n) { d.addEventListener('click', function (e) { e.stopPropagation(); stop(); play(n); }); });
    if (canHover) {
      ba.addEventListener('mouseenter', function () { if (auto) { ba.classList.add('paused'); clear(); sets[cur].classList.add('struck', 'written'); } });
      ba.addEventListener('mouseleave', function () { if (auto) { ba.classList.remove('paused', 'playing'); timers.push(setTimeout(function () { play(cur + 1); }, 2500)); } });
    }
    ba.addEventListener('focusin', function () { if (auto) { clear(); ba.classList.add('paused'); } });
    // touch: a tap pauses or resumes, a sideways swipe changes the example
    var tx = null, ty = null;
    ba.addEventListener('touchstart', function (e) { tx = e.touches[0].clientX; ty = e.touches[0].clientY; }, { passive: true });
    ba.addEventListener('touchend', function (e) {
      if (tx === null) return; var dx = e.changedTouches[0].clientX - tx, dy = e.changedTouches[0].clientY - ty; tx = null;
      if (Math.abs(dx) > 40 && Math.abs(dx) > Math.abs(dy) * 1.5) { stop(); play(cur + (dx < 0 ? 1 : -1)); }
      else if (Math.abs(dx) < 8 && Math.abs(dy) < 8 && !e.target.closest('button')) { if (auto) stop(); else { auto = true; play(cur + 1); } }
    }, { passive: true });
    if (hasIO) new IntersectionObserver(function (en) {
      onScreen = en[0].isIntersecting;
      if (!onScreen) { clear(); ba.classList.remove('playing'); sets[cur].classList.add('struck', 'written'); }
      else if (auto) play(cur, true);
    }, { threshold: 0.25 }).observe(ba);
    document.addEventListener('visibilitychange', function () { if (document.hidden) clear(); else if (auto && onScreen) play(cur, true); });
    play(0);
  }

  /* ---------- FAQ: height eases open and closed ---------- */
  $$('.faq details').forEach(function (d) {
    var sum = $('summary', d), body = $('.a', d); if (!body || !body.animate || reduce) return;
    sum.addEventListener('click', function (e) {
      e.preventDefault();
      if (d.open) {
        var a = body.animate([{ height: body.offsetHeight + 'px', opacity: 1 }, { height: '0px', opacity: 0 }], { duration: 260, easing: 'cubic-bezier(.2,.7,.2,1)' });
        a.onfinish = function () { d.open = false; };
      } else {
        d.open = true;
        body.animate([{ height: '0px', opacity: 0 }, { height: body.offsetHeight + 'px', opacity: 1 }], { duration: 300, easing: 'cubic-bezier(.2,.7,.2,1)' });
      }
    });
  });

  /* ---------- Forms: a tick when a field is good, a sending state on submit ---------- */
  $$('form[name] .field').forEach(function (f) {
    var el = $('input, textarea', f); if (!el) return;
    el.addEventListener('blur', function () { f.classList.toggle('ok', !!el.value.trim() && el.checkValidity()); });
  });
  $$('form[name]').forEach(function (form) {
    form.addEventListener('submit', function () { var b = $('button[type=submit]', form); if (b) { b.classList.add('sending'); b.firstChild.nodeValue = 'Sending'; } });
  });

  /* ---------- Clarity tester: rule based, runs here, nothing is sent ---------- */
  var tf = $('#tester');
  if (tf) {
    var JARGON = ['leverage', 'leveraging', 'leveraged', 'robust', 'robustness', 'solution', 'solutions', 'platform', 'innovative', 'innovation', 'synergy', 'synergies', 'seamless', 'seamlessly', 'cutting edge', 'world class', 'best in class', 'best of breed', 'end to end', 'turnkey', 'holistic', 'ecosystem', 'paradigm', 'disruptive', 'disrupt', 'revolutionary', 'revolutionise', 'revolutionize', 'next generation', 'state of the art', 'bespoke', 'scalable', 'optimise', 'optimize', 'optimisation', 'optimization', 'utilise', 'utilize', 'empower', 'empowering', 'enable', 'enabling', 'enablement', 'unlock', 'unlocking', 'transformative', 'transformation', 'mission critical', 'value add', 'value added', 'stakeholders', 'tokenisation', 'tokenization', 'blockchain', 'ai powered', 'ai driven', 'data driven', 'cloud based', 'omnichannel', 'frictionless', 'passionate', 'premium', 'quality', 'artisanal', 'unique', 'leading', 'provider', 'full service', 'one stop shop', 'tailored', 'customer centric', 'dynamic', 'strategic', 'facilitate', 'streamline', 'streamlined', 'framework', 'proprietary', 'integrated', 'comprehensive', 'telemetry', 'iot'];
    var esc = function (s) { return s.replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); };
    var out = $('#tester-result'), ta = $('#tester-text');
    tf.addEventListener('submit', function (e) {
      e.preventDefault();
      var text = ta.value.trim().replace(/\s+/g, ' '); if (!text) { ta.focus(); return; }
      var n = text.split(' ').filter(Boolean).length;
      var sentences = text.split(/[.!?]+/).filter(function (s) { return s.trim(); });
      var longest = Math.max.apply(null, sentences.map(function (s) { return s.trim().split(' ').length; }));
      var found = [], marked = esc(text);
      JARGON.slice().sort(function (a, b) { return b.length - a.length; }).forEach(function (j) {
        var re = new RegExp('(^|[^a-z<>])(' + j.replace(/ /g, '[ -]') + ')(?![a-z])', 'gi');
        if (re.test(marked)) { found.push(j); marked = marked.replace(re, '$1<mark>$2</mark>'); }
      });
      var you = /\b(you|your|you're)\b/i.test(text), we = (text.match(/\b(we|our|us)\b/gi) || []).length;
      var score = 100, notes = [];
      if (found.length) { score -= Math.min(45, found.length * 12); notes.push('<b>' + found.length + (found.length === 1 ? ' word' : ' words') + ' doing no work.</b> The highlighted words sound like everyone else. Swap each for the plain thing it stands for.'); }
      if (longest > 24) { score -= 20; notes.push('<b>One sentence runs to ' + longest + ' words.</b> If you cannot say it in one breath, a customer cannot repeat it.'); }
      if (n > 45) { score -= 10; notes.push('<b>It is ' + n + ' words long.</b> Aim for under 25. What would you cut first?'); }
      if (n < 5) { score -= 25; notes.push('<b>Very short.</b> Short is good, but it still has to say who it is for and what they get.'); }
      if (!you && we > 0) { score -= 15; notes.push('<b>It is all about you.</b> There is no &ldquo;you&rdquo; or &ldquo;your&rdquo;. Say what the customer gets, not what you are.'); }
      if (!/\d/.test(text) && !/\b(so|which means|without|instead of|before|faster|cheaper|less|more|save|saves)\b/i.test(text)) { score -= 10; notes.push('<b>No outcome.</b> Nothing here says what changes for the customer: time, money, risk, or a result they can picture.'); }
      score = Math.max(12, Math.min(100, score));
      var verdict = score >= 85 ? 'That is already pretty clear.' : score >= 60 ? 'Close. A customer would get most of it.' : score >= 40 ? 'A customer would nod politely and forget it.' : 'This is hiding what you sell.';
      if (!notes.length) notes.push('<b>No obvious problems.</b> The real test is whether a stranger can repeat it back an hour later. That is what the call is for.');
      out.innerHTML = '<h3>' + verdict + '</h3><div class="meter" role="img" aria-label="Clarity ' + score + ' out of 100"><i></i></div><p class="echo">' + marked + '</p><ul>' + notes.map(function (x) { return '<li>' + x + '</li>'; }).join('') + '</ul><a class="btn" href="#start" id="tester-go">Get a person to fix it</a><p class="fine">This is a quick rule based check that runs in your browser. Nothing you type is sent or stored. The real work is done by a person.</p>';
      out.classList.remove('on', 'lit'); void out.offsetWidth; out.classList.add('on');
      // the cause first (highlights sweep in one by one), then the score
      var marks = $$('mark', out); marks.forEach(function (m, k) { m.style.setProperty('--k', Math.min(k, 12)); });
      setTimeout(function () { out.classList.add('lit'); }, 40);
      setTimeout(function () { $('.meter i', out).style.width = score + '%'; }, reduce ? 0 : 250 + Math.min(marks.length, 12) * 60);
      $('#tester-go').addEventListener('click', function () { var m = $('#f-msg'); if (m && !m.value) m.value = text; });
      out.setAttribute('tabindex', '-1'); out.focus({ preventScroll: true });
      if (!desktop.matches) out.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'nearest' });
    });
  }

  /* ---------- Home proof loops: play only while on screen ---------- */
  $$('video.inview').forEach(function (v) {
    if (reduce || !hasIO) { v.setAttribute('controls', ''); return; }
    new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) { var p = v.play(); if (p && p.catch) p.catch(function () { /* autoplay blocked: keep the poster, a tap plays it */ v.style.cursor = 'pointer'; v.onclick = function () { v.paused ? v.play() : v.pause(); }; }); }
        else v.pause();
      });
    }, { threshold: 0.35 }).observe(v);
  });

  /* ---------- Case study videos: poster with a play button, controls appear once playing ---------- */
  $$('.vid video').forEach(function (v) {
    v.removeAttribute('controls');
    var b = document.createElement('button'); b.type = 'button'; b.className = 'play';
    b.setAttribute('aria-label', 'Play video: ' + (v.getAttribute('aria-label') || ''));
    b.innerHTML = '<span></span>' + (v.getAttribute('data-len') ? '<em>' + v.getAttribute('data-len') + '</em>' : '');
    v.parentNode.appendChild(b);
    b.addEventListener('click', function () {
      $$('.vid video').forEach(function (o) { if (o !== v) o.pause(); });
      v.setAttribute('controls', ''); b.style.display = 'none'; v.play(); v.focus();
    });
  });

  /* ---------- Gallery: show the full set ---------- */
  $$('[data-more]').forEach(function (b) {
    b.addEventListener('click', function () {
      var m = document.getElementById(b.getAttribute('data-more'));
      m.classList.add('all'); b.parentNode.style.display = 'none';
      var first = m.querySelector('.more button'); if (first) first.focus();
    });
  });

  /* ---------- Lightbox: keyboard, preload, and the image follows the finger ---------- */
  var lb, lbImg, lbCount, set = [], at = 0, opener = null;
  function visible() { return $$('button[data-full]').filter(function (b) { return b.offsetParent !== null; }); }
  function show(i) {
    at = (i + set.length) % set.length;
    var src = (set[at].getAttribute('data-full')||set[at].querySelector('img').src);
    lbImg.classList.add('swap');
    var pre = new Image(); pre.onload = pre.onerror = function () {
      lbImg.style.transform = ''; lbImg.src = src; lbImg.alt = (set[at].querySelector('img') || {}).alt || ''; lbImg.classList.remove('swap');
      var nx = set[(at + 1) % set.length]; if (nx) { new Image().src = (nx.getAttribute('data-full')||nx.querySelector('img').src); }
    }; pre.src = src;
    lbCount.textContent = (at + 1) + ' of ' + set.length;
  }
  function close() { lb.classList.remove('open'); setTimeout(function () { lb.style.display = 'none'; lbImg.removeAttribute('src'); }, 250); document.body.style.overflow = ''; if (opener) opener.focus(); }
  function build() {
    lb = document.createElement('div'); lb.className = 'lb'; lb.setAttribute('role', 'dialog'); lb.setAttribute('aria-modal', 'true'); lb.setAttribute('aria-label', 'Image viewer');
    lb.innerHTML = '<button class="x" type="button">Close</button><button class="p" type="button" aria-label="Previous image">Prev</button><img alt=""><button class="n" type="button" aria-label="Next image">Next</button><div class="count" aria-live="polite"></div>';
    document.body.appendChild(lb);
    lbImg = $('img', lb); lbCount = $('.count', lb);
    $('.x', lb).addEventListener('click', close);
    $('.p', lb).addEventListener('click', function () { show(at - 1); });
    $('.n', lb).addEventListener('click', function () { show(at + 1); });
    lb.addEventListener('click', function (e) { if (e.target === lb) close(); });
    var x0 = null, dx = 0;
    lb.addEventListener('touchstart', function (e) { if (e.target.closest('button')) return; x0 = e.touches[0].clientX; dx = 0; lbImg.classList.add('drag'); }, { passive: true });
    lb.addEventListener('touchmove', function (e) { if (x0 === null) return; dx = e.touches[0].clientX - x0; lbImg.style.transform = 'translateX(' + dx + 'px)'; lbImg.style.opacity = String(Math.max(.35, 1 - Math.abs(dx) / 500)); }, { passive: true });
    lb.addEventListener('touchend', function () {
      if (x0 === null) return; x0 = null; lbImg.classList.remove('drag'); lbImg.style.opacity = '';
      if (Math.abs(dx) > 60) { lbImg.style.transform = 'translateX(' + (dx < 0 ? -100 : 100) + 'vw)'; setTimeout(function () { show(at + (dx < 0 ? 1 : -1)); }, 180); }
      else lbImg.style.transform = '';
    }, { passive: true });
    document.addEventListener('keydown', function (e) {
      if (!lb.classList.contains('open')) return;
      if (e.key === 'Escape') close();
      if (e.key === 'ArrowLeft') show(at - 1);
      if (e.key === 'ArrowRight') show(at + 1);
      if (e.key === 'Tab') { var f = $$('button', lb), i = f.indexOf(document.activeElement); e.preventDefault(); f[(i + (e.shiftKey ? -1 : 1) + f.length) % f.length].focus(); }
    });
  }
  document.addEventListener('click', function (e) {
    var b = e.target.closest ? e.target.closest('button[data-full]') : null; if (!b) return;
    if (!lb) build();
    set = visible(); opener = b; lb.style.display = 'flex';
    requestAnimationFrame(function () { lb.classList.add('open'); });
    show(set.indexOf(b)); document.body.style.overflow = 'hidden'; $('.x', lb).focus();
  });

  /* ---------- Phone call bar: after the hero, never over the form, never while typing ---------- */
  var cb = $('.callbar');
  if (cb && hasIO) {
    var pastHero = false, atEnd = false, seen = {};
    var first = $('.hero-text') || $('.page-head'), ends = $$('#start, .cta-band, .site-foot');
    var sync = function () {
      var on = pastHero && !atEnd && !desktop.matches && !typing();
      cb.classList.toggle('on', on);
      root.style.setProperty('--callbar-h', on ? cb.offsetHeight + 'px' : '0px');
    };
    new IntersectionObserver(function (en) { pastHero = !en[0].isIntersecting && en[0].boundingClientRect.top < 0; sync(); }).observe(first);
    var ioe = new IntersectionObserver(function (en) { en.forEach(function (x) { seen[x.target.className + x.target.id] = x.isIntersecting; }); atEnd = Object.keys(seen).some(function (k) { return seen[k]; }); sync(); });
    ends.forEach(function (el) { ioe.observe(el); });
    document.addEventListener('focusin', sync); document.addEventListener('focusout', function () { setTimeout(sync, 50); });
  }

  var yr = $('#yr'); if (yr) yr.textContent = new Date().getFullYear();
})();
