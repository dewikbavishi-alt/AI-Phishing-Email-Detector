"""
Test the trained detector on realistic emails that are NOT in the dataset.

The training data is synthetic, so the held-out test score (100%) is too
optimistic. This script shows how the model does on emails written the way
real phishing and real business email look.
"""

from utils.analyzer import analyze_email

# (expected label, subject, body)
EMAILS = [
    ("Phishing", "Your Microsoft 365 password expires today",
     "Dear user,\nYour Office 365 password will expire in 24 hours. To keep using your "
     "mailbox, confirm your current password here: "
     "http://microsoft-365-login.secure-verify.xyz/owa\nIT Helpdesk"),
    ("Phishing", "Delivery failed",
     "Hi, we tried to deliver your parcel but no one was home. Pay the $1.99 redelivery "
     "fee within 48 hours or your package will be returned: https://bit.ly/3xYpkg"),
    ("Phishing", "Invoice #88231",
     "Hello, please find attached the overdue invoice. Kindly process the wire transfer "
     "to our new bank account today, as our old account is under audit. "
     "Regards, Accounts Payable"),
    ("Phishing", "Account limited",
     "Your PayPal account has been limited. Log in to restore full access: "
     "http://paypal.account-restore.com/signin"),
    ("Phishing", "Unusual activity",
     "Dear Customer, we noticed unusual activity on your account and have temporarily "
     "limited it. To restore full access, please log in and verify your information "
     "within 24 hours."),
    ("Safe", "Team lunch Friday",
     "Hey all, we're doing team lunch on Friday at 1pm at the Italian place near the "
     "office. Reply if you have dietary restrictions. Thanks, Priya"),
    ("Safe", "Your order has shipped",
     "Hi Dewik, good news! Your order #402-1133 has shipped and will arrive on Monday. "
     "Track it in your Amazon account under Your Orders. Thanks for shopping with us."),
    ("Safe", "Re: project report",
     "Thanks for sending the draft. I added comments on section 3 and the references. "
     "Can we meet Tuesday to go over the final version?"),
    ("Safe", "Password changed",
     "Hi, the password for your GitHub account was changed. If this was you, no action "
     "is needed. If not, please contact support."),
    ("Safe", "[GitHub] Your pull request was merged",
     "Hi there,\nYour pull request \"Fix typo in README\" was merged into main by a "
     "maintainer.\nView it on GitHub: https://github.com/example/project/pull/42\n"
     "Thanks for contributing!"),
]


def main():
    correct = 0

    print(f"{'Expected':10} {'Verdict':11} {'Risk':>4}  {'ML %':>5}  Subject")
    print("-" * 72)

    for expected, subject, body in EMAILS:
        result = analyze_email(body, subject)

        # "Suspicious" counts as a catch for phishing, and as a false alarm for safe mail
        predicted = "Safe" if result["verdict"] == "Safe" else "Phishing"
        ok = predicted == expected
        correct += ok

        print(
            f"{expected:10} {result['verdict']:11} {result['risk_score']:>4}  "
            f"{result['ml_probability'] * 100:>5.1f}  {subject}  {'OK' if ok else 'WRONG'}"
        )

    print("-" * 72)
    print(f"Correct: {correct}/{len(EMAILS)}")


if __name__ == "__main__":
    main()
