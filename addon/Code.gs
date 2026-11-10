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

// Called by Gmail whenever the user opens an email
function onGmailMessageOpen(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  const message = GmailApp.getMessageById(e.gmail.messageId);

  // Send only the fields the backend needs, trimmed to its size limits
  const emailData = {
    sender: (message.getFrom() || '').slice(0, 500),
    subject: (message.getSubject() || '').slice(0, 1000)
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

// Builds the card with the verdict, score and reasons
function buildResultCard(emailData, result) {
  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Second Look'));

  const summary = CardService.newCardSection()
    .addWidget(CardService.newDecoratedText()
      .setTopLabel('Verdict')
      .setText(escapeHtml(result.verdict) + ' (' + Number(result.score) + '/100)')
      .setWrapText(true))
    .addWidget(CardService.newDecoratedText()
      .setTopLabel('From')
      .setText(escapeHtml(emailData.sender))
      .setWrapText(true));
  card.addSection(summary);

  // A section must contain at least one widget, so add it only if there are reasons
  const reasons = result.reasons || [];
  if (reasons.length > 0) {
    const reasonsSection = CardService.newCardSection().setHeader('Why');
    reasons.forEach(function (reason) {
      reasonsSection.addWidget(CardService.newDecoratedText()
        .setText(escapeHtml(reason.detail))
        .setBottomLabel('+' + Number(reason.points) + ' points')
        .setWrapText(true));
    });
    card.addSection(reasonsSection);
  }

  return card.build();
}

// Shown when the analysis fails; reveals no technical details to the user
function buildErrorCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Second Look'))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph()
        .setText('Could not analyze this email right now. Please try again in a moment.')))
    .build();
}

// Email content and backend responses are untrusted: escape before rendering
function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}