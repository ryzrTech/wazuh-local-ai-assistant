import React from 'react';
import { EuiMarkdownFormat, getDefaultEuiMarkdownParsingPlugins } from '@elastic/eui';
import { stripUnsafeMarkdown } from './markdown_safety';

const parsingPluginList = [...getDefaultEuiMarkdownParsingPlugins(), [stripUnsafeMarkdown, {}]];

export function AssistantMarkdown({ content }: { content: string }) {
  return <div className="wlaMarkdown"><EuiMarkdownFormat parsingPluginList={parsingPluginList}>{content}</EuiMarkdownFormat></div>;
}
