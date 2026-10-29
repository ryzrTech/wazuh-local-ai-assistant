// Some OpenAI-compatible models put reasoning in content instead of reasoning_content.
// Keep those tags out of the answer while the closing tag is still streaming.
export function splitThinkTags(content: string) {
  let answer = '';
  let thinking = '';
  let offset = 0;
  let active = false;
  while (offset < content.length) {
    const open = /<think>/i.exec(content.slice(offset));
    if (!open) {
      const rest = content.slice(offset);
      const lastTag = rest.lastIndexOf('<');
      if (lastTag >= 0 && '<think>'.startsWith(rest.slice(lastTag).toLowerCase())) {
        answer += rest.slice(0, lastTag);
        active = true;
      } else answer += rest;
      break;
    }
    answer += content.slice(offset, offset + open.index);
    const start = offset + open.index + open[0].length;
    const close = /<\/think>/i.exec(content.slice(start));
    if (!close) {
      const rest = content.slice(start);
      const lastTag = rest.lastIndexOf('<');
      thinking += lastTag >= 0 && '</think>'.startsWith(rest.slice(lastTag).toLowerCase()) ? rest.slice(0, lastTag) : rest;
      active = true;
      break;
    }
    thinking += content.slice(start, start + close.index);
    offset = start + close.index + close[0].length;
  }
  return { answer, thinking, active };
}
