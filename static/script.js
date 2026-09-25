const SAMPLES = {
  phishing: {
    sender: "Microsoft 365 <no-reply@m365-alerts.xyz>",
    subject: "Action required: your password expires today",
    body: "Dear user,\n\nYour Office 365 password will expire in 24 hours. To keep access to your mailbox, confirm your current password immediately using the secure link below:\n\nhttp://microsoft-365-login.secure-verify.xyz/owa/verify\n\nFailure to verify will result in your account being suspended.\n\nIT Helpdesk"
  },
  parcel: {
    sender: "Delivery Service <notice@parcel-track-help.top>",
    subject: "Delivery failed - action needed",
    body: "Hi,\n\nWe tried to deliver your parcel today but no one was home. Please pay the $1.99 redelivery fee within 48 hours or your package will be returned to the sender:\n\nhttps://bit.ly/3xYpkg\n\nThank you,\nCustomer Care"
  },
  safe: {
    sender: "Priya Shah <priya@company.com>",
    subject: "Team lunch on Friday",
    body: "Hey all,\n\nWe're doing a team lunch on Friday at 1pm at the Italian place near the office. Reply to this email if you have any dietary restrictions so I can let them know.\n\nThanks,\nPriya"
  }
};

const body = document.getElementById("body");
const counter = document.getElementById("char-count");

function updateCount() {
  if (body && counter) {
    counter.textContent = body.value.length.toLocaleString() + " characters";
  }
}

if (body) {
  body.addEventListener("input", updateCount);

  document.querySelectorAll("[data-sample]").forEach((button) => {
    button.addEventListener("click", () => {
      const sample = SAMPLES[button.dataset.sample];
      document.getElementById("sender").value = sample.sender;
      document.getElementById("subject").value = sample.subject;
      body.value = sample.body;
      updateCount();
    });
  });
}

const fileInput = document.getElementById("email_file");
if (fileInput) {
  fileInput.addEventListener("change", () => {
    const label = document.getElementById("file-label");
    if (fileInput.files.length) {
      label.textContent = "Selected: " + fileInput.files[0].name;
    }
  });
}

const form = document.getElementById("analyze-form");
if (form) {
  form.addEventListener("submit", () => {
    const button = document.getElementById("submit-btn");
    button.disabled = true;
    button.textContent = "Analyzing...";
  });
}
