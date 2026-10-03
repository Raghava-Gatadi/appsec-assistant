// Synthetic static scan fixture; do not run or deploy.
import { exec as runCommand } from 'node:child_process';

function renderPreview(value: string, target: HTMLElement) {
  target.innerHTML = value;
}

function executeMaintenance(command: string) {
  runCommand(command);
}

app.get('/accounts', (req, res) => {
  db.query(`SELECT id FROM accounts WHERE name = ${req.query.name}`);
});

function safeLabel(value: string, target: HTMLElement) {
  target.textContent = value;
}
