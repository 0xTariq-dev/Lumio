import { useEffect, useState } from 'react';
import { motion, useReducedMotion } from 'framer-motion';

const CHARACTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()-+=[]{}|;:,.<>?';

export function AnimatedTagline({ text, reveal, leaving, decrypt = true }: { text: string; reveal: boolean; leaving: boolean; decrypt?: boolean }) {
  const reducedMotion = useReducedMotion();
  const [scrambled, setScrambled] = useState(text);

  useEffect(() => {
    if (reveal || reducedMotion || !decrypt) return;
    let frame = 0;
    let started: number | undefined;
    const scramble = (now: number) => {
      started ??= now;
      const progress = Math.min((now - started) / 1400, 1);
      setScrambled(text.split('').map((character, index) => {
        if (/\s/.test(character) || index < progress * text.length) return character;
        return CHARACTERS[Math.floor(Math.random() * CHARACTERS.length)];
      }).join(''));
      if (progress < 1) frame = requestAnimationFrame(scramble);
    };
    frame = requestAnimationFrame(scramble);
    return () => cancelAnimationFrame(frame);
  }, [text, reveal, reducedMotion, decrypt]);

  return (
    <>
      <span className="sr-only">{text}</span>
      {reveal ? (
        <motion.span aria-hidden="true" className="tagline-reveal" initial="hidden" animate="visible"
          variants={{ hidden: {}, visible: { transition: { delayChildren: reducedMotion ? 0 : 0.65, staggerChildren: reducedMotion ? 0 : 0.04 } } }}>
          {text.split(' ').map((word, index) => (
            <span key={index} className="inline-block whitespace-nowrap">
              <motion.span className="inline-block" variants={{ hidden: { opacity: 0, y: reducedMotion ? 0 : 20, filter: reducedMotion ? 'blur(0px)' : 'blur(10px)' }, visible: { opacity: 1, y: 0, filter: 'blur(0px)' } }}
                transition={{ duration: reducedMotion ? 0 : 0.8, ease: [0.25, 0.46, 0.45, 0.94] }}>{word}</motion.span>
              {index < text.split(' ').length - 1 ? '\u00a0' : ''}
            </span>
          ))}
        </motion.span>
      ) : (
        <motion.span aria-hidden="true" className="tagline-decrypt" initial={{ opacity: reducedMotion ? 1 : 0 }} animate={{ opacity: leaving ? 0 : 1 }} transition={{ duration: reducedMotion ? 0 : 0.35 }}>
          {text.split(/(\s+)/).map((part, partIndex, parts) => {
            const offset = parts.slice(0, partIndex).join('').length;
            if (/^\s+$/.test(part)) return part;
            return <span key={partIndex} className="inline-block whitespace-nowrap">{part.split('').map((character, index) => (
              <span key={index} className="tagline-character">
                <span className="invisible">{character}</span>
                <span className="tagline-scramble">{reducedMotion || !decrypt ? character : scrambled[offset + index]}</span>
              </span>
            ))}</span>;
          })}
        </motion.span>
      )}
    </>
  );
}