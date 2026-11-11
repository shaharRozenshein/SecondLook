/**
 * Second Look - Gmail Add-on
 *
 * oauthScopes (least privilege):
 *   - gmail.addons.execute: run inside Gmail.
 *   - gmail.addons.current.message.readonly: read the open email only.
 *   - script.external_request: call our backend over HTTPS.
 * urlFetchWhitelist: the only URLs the add-on may call (our backend).
 * contextualTriggers: run onGmailMessageOpen every time an email is opened.
 *
 * Secrets: BACKEND_URL and API_KEY are stored in Script Properties, not in code.
 */
// Visual style and advice for each verdict. Unknown verdicts fall back to a neutral style.
const VERDICT_STYLES = {
  'Low risk': {
    color: '#188038', icon: '🟢',
    advice: 'No warning signs found. Stay alert as usual and verify unexpected requests.'
  },
  'Suspicious': {
    color: '#b06000', icon: '🟡',
    advice: 'Be careful. Do not click links, open attachments or share details until you verify the sender another way.'
  },
  'Likely phishing': {
    color: '#c5221f', icon: '🔴',
    advice: 'Do not click links, open attachments or reply. Report it: open the ⋮ menu and choose "Report phishing".'
  }
};
const DEFAULT_STYLE = { color: '#5f6368', icon: '⚪', advice: 'Review this email carefully before acting on it.' };

// Called by Gmail whenever the user opens an email
function onGmailMessageOpen(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  const message = GmailApp.getMessageById(e.gmail.messageId);
  const attachments = message.getAttachments({ includeInlineImages: false });

  // Send only what the analysis needs, trimmed to the backend's size limits.
  // Attachment contents never leave Google: only name, type and size are sent.
  const emailData = {
    sender: truncate(message.getFrom(), 500),
    reply_to: truncate(message.getReplyTo(), 500),
    subject: truncate(message.getSubject(), 1000),
    auth_results: truncate(message.getHeader('Authentication-Results'), 5000),
    body_text: truncate(message.getPlainBody(), 50000),
    body_html: truncate(message.getBody(), 200000),
    attachments: attachments.slice(0, 20).map(function (attachment) {
      return {
        name: truncate(attachment.getName(), 300),
        content_type: truncate(attachment.getContentType(), 200),
        size: attachment.getSize()
      };
    }),
    attachment_count: attachments.length
  };

  const result = analyzeEmail(emailData);
  if (!result) {
    return [buildErrorCard()];
  }
  return [buildResultCard(emailData, result)];
}

// Sends the email data to the backend; returns the analysis, or null on any failure
function analyzeEmail(emailData) {
  const props = PropertiesService.getScriptProperties();
  const backendUrl = props.getProperty('BACKEND_URL');
  const apiKey = props.getProperty('API_KEY');
  if (!backendUrl || !apiKey) {
    console.error('Missing BACKEND_URL or API_KEY in Script Properties');
    return null;
  }

  try {
    const response = UrlFetchApp.fetch(backendUrl + '/analyze', {
      method: 'post',
      contentType: 'application/json',
      headers: { 'X-API-Key': apiKey },
      payload: JSON.stringify(emailData),
      muteHttpExceptions: true
    });
    if (response.getResponseCode() !== 200) {
      console.error('Backend returned status ' + response.getResponseCode());
      return null;
    }
    return JSON.parse(response.getContentText());
  } catch (err) {
    console.error('Backend request failed: ' + err.message);
    return null;
  }
}

// Builds the card with the verdict, score, advice and reasons
function buildResultCard(emailData, result) {
  const known = Object.prototype.hasOwnProperty.call(VERDICT_STYLES, result.verdict);
  const style = known ? VERDICT_STYLES[result.verdict] : DEFAULT_STYLE;
  const verdict = known ? result.verdict : 'Unknown result';
  const score = Math.max(0, Math.min(100, Number(result.score) || 0));

  // The header is the largest text on the card, so it carries the verdict and the score
  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle(ltr(style.icon + ' ' + verdict))
      .setSubtitle(ltr('Risk score: ' + score + ' / 100 (higher = more suspicious)')));

  // What to do next, highlighted in the verdict's color
  card.addSection(CardService.newCardSection()
    .addWidget(CardService.newTextParagraph()
      .setText(ltr('<font color="' + style.color + '"><b>What to do</b></font>') + '<br>' + ltr(style.advice))));

  // Reasons, most serious first (the backend already sorts them)
  const reasons = Array.isArray(result.reasons) ? result.reasons : [];
  const why = CardService.newCardSection().setHeader('Why this verdict');
  if (reasons.length === 0) {
    why.addWidget(CardService.newTextParagraph()
      .setText(ltr('No warning signs were found in this email.')));
  }
  reasons.forEach(function (reason) {
    why.addWidget(CardService.newDecoratedText()
      .setText(ltr(escapeHtml(reason.detail)))
      .setBottomLabel(ltr('+' + Number(reason.points) + ' points'))
      .setWrapText(true));
  });
  card.addSection(why);

  // Analyzed email and an honest reminder of what the tool can and cannot do
  card.addSection(CardService.newCardSection()
    .setHeader('Email details')
    .addWidget(CardService.newDecoratedText()
      .setTopLabel('From')
      .setText(ltr(escapeHtml(emailData.sender)))
      .setWrapText(true))
    .addWidget(CardService.newTextParagraph()
      .setText(ltr('<i>Second Look gives a second opinion, not a guarantee. When in doubt, verify with the sender directly.</i>'))));

  return card.build();
}

// Shown when the analysis fails; reveals no technical details to the user
function buildErrorCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('⚪ Could not analyze this email')
      .setSubtitle('Please try again in a moment'))
    .build();
}

// Email content and backend responses are untrusted: escape before rendering
function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// Converts any value to text and trims it to the backend's size limit
function truncate(value, maxLength) {
  return String(value || '').slice(0, maxLength);
}

// Wraps text in Unicode left-to-right isolation marks, so English text and symbols
// (like "+5 points" or "<name@domain>") display correctly when Gmail is right-to-left
function ltr(text) {
  return '\u2066' + text + '\u2069';
}