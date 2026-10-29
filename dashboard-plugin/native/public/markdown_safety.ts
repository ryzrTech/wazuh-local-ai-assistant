// Model output is untrusted. Keep Markdown formatting while preventing HTML and
// image nodes from creating elements or fetching remote content.
export function stripUnsafeMarkdown() {
  return (tree: any) => {
    const walk = (node: any) => {
      if (!Array.isArray(node.children)) return;
      node.children.forEach((child: any) => {
        if (child.type === 'html') {
          child.type = 'text';
        } else if (child.type === 'image' || child.type === 'imageReference') {
          child.value = child.alt ? `[Image: ${child.alt}]` : '[Image]';
          child.type = 'text';
          delete child.url;
          delete child.identifier;
          delete child.referenceType;
          delete child.alt;
          delete child.title;
        } else if (child.type === 'linkReference') {
          child.value = child.children.map((part: any) => part.value || '').join('');
          child.type = 'text';
          delete child.children;
          delete child.identifier;
          delete child.referenceType;
          delete child.label;
        } else {
          walk(child);
        }
      });
    };
    walk(tree);
  };
}
