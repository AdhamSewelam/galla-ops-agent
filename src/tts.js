// Free text-to-speech on the VPS for JARVIS voice messages.
// 1st choice: Piper (open source, natural British voice "en_GB-alan-medium").
// Fallback: espeak-ng (robotic). Output: OGG/Opus, the format Telegram voice messages need (via ffmpeg).
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

function run(cmd, args, { input = null, timeoutMs = 60000 } = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: ['pipe', 'ignore', 'pipe'] });
    let err = '';
    const t = setTimeout(() => { p.kill('SIGKILL'); reject(new Error(`${cmd} timed out`)); }, timeoutMs);
    p.stderr.on('data', (d) => { err += d; });
    p.on('error', (e) => { clearTimeout(t); reject(e); });
    p.on('close', (code) => { clearTimeout(t); code === 0 ? resolve() : reject(new Error(`${cmd} exited ${code}: ${err.slice(-200)}`)); });
    if (input != null) p.stdin.end(input); else p.stdin.end();
  });
}

/** Returns { file, engine } with an .ogg voice file, or null if no TTS engine is installed. Caller deletes the file. */
export async function synthesize(text, { piperModel = null, python = 'python3' } = {}) {
  const base = path.join(os.tmpdir(), `jarvis-${crypto.randomUUID()}`);
  const wav = `${base}.wav`, ogg = `${base}.ogg`;
  const attempts = [];
  if (piperModel && fs.existsSync(piperModel)) {
    attempts.push(['piper', () => run(python, ['-m', 'piper', '-m', piperModel, '-f', wav, '--length-scale', '1.05'], { input: text })]);
  }
  attempts.push(['espeak-ng', () => run('espeak-ng', ['-v', 'en-gb', '-s', '150', '-p', '35', '-w', wav, text])]);
  for (const [engine, go] of attempts) {
    try {
      await go();
      await run('ffmpeg', ['-y', '-loglevel', 'error', '-i', wav, '-ac', '1', '-c:a', 'libopus', '-b:a', '32k', ogg]);
      fs.rmSync(wav, { force: true });
      return { file: ogg, engine };
    } catch {
      fs.rmSync(wav, { force: true });
    }
  }
  return null;
}
