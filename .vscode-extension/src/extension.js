const vscode = require('vscode');
const { execSync } = require('child_process');
const path = require('path');

let diagnosticCollection;

function activate(context) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('gitguard');

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('gitguard.scan', () => scanCurrentFile()),
        vscode.commands.registerCommand('gitguard.scanProject', () => scanProject()),
        vscode.commands.registerCommand('gitguard.fix', () => autoFix()),
        vscode.commands.registerCommand('gitguard.explain', () => explainFinding()),
        vscode.commands.registerCommand('gitguard.history', () => scanHistory())
    );

    // Scan on save if enabled
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((document) => {
            const config = vscode.workspace.getConfiguration('gitguard');
            if (config.get('scanOnSave') && config.get('enabled')) {
                scanFile(document.fileName);
            }
        })
    );

    // Scan open files
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument((document) => {
            const config = vscode.workspace.getConfiguration('gitguard');
            if (config.get('enabled')) {
                scanFile(document.fileName);
            }
        })
    );

    // Scan workspace on activation
    if (vscode.workspace.workspaceFolders) {
        scanProject();
    }
}

function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
}

async function scanCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active editor');
        return;
    }
    await scanFile(editor.document.fileName);
}

async function scanProject() {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
        vscode.window.showWarningMessage('No workspace folder found');
        return;
    }

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'GitGuard: Scanning project...',
        cancellable: false
    }, async (progress) => {
        try {
            const result = execSync(
                `gitguard scan "${workspaceFolder.uri.fsPath}" --output /tmp/gitguard-results.json`,
                { encoding: 'utf-8', timeout: 60000 }
            );

            const findings = JSON.parse(
                require('fs').readFileSync('/tmp/gitguard-results.json', 'utf-8')
            );

            updateDiagnostics(findings);
            vscode.window.showInformationMessage(
                `GitGuard: Found ${findings.length} issues`
            );
        } catch (error) {
            vscode.window.showErrorMessage(`GitGuard scan failed: ${error.message}`);
        }
    });
}

async function scanFile(filePath) {
    try {
        const result = execSync(
            `gitguard scan "${filePath}" --output /tmp/gitguard-file.json`,
            { encoding: 'utf-8', timeout: 30000 }
        );

        const findings = JSON.parse(
            require('fs').readFileSync('/tmp/gitguard-file.json', 'utf-8')
        );

        const document = vscode.workspace.textDocuments.find(
            doc => doc.fileName === filePath
        );

        if (document) {
            const diagnostics = findings.map(finding => {
                const range = new vscode.Range(
                    new vscode.Position(finding.line - 1, 0),
                    new vscode.Position(finding.line - 1, 1000)
                );

                const severity = mapSeverity(finding.severity);
                const diagnostic = new vscode.Diagnostic(
                    range,
                    `[${finding.rule}] ${finding.message}`,
                    severity
                );

                diagnostic.source = 'GitGuard';
                diagnostic.code = finding.rule;

                if (finding.suggestion) {
                    diagnostic.relatedInformation = [
                        new vscode.DiagnosticRelatedInformation(
                            new vscode.Location(document.uri, range),
                            finding.suggestion
                        )
                    ];
                }

                return diagnostic;
            });

            diagnosticCollection.set(document.uri, diagnostics);
        }
    } catch (error) {
        // Silent fail for background scanning
    }
}

async function autoFix() {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
        vscode.window.showWarningMessage('No workspace folder found');
        return;
    }

    const choice = await vscode.window.showWarningMessage(
        'Auto-fix security issues in your project?',
        'Fix All',
        'Cancel'
    );

    if (choice === 'Fix All') {
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'GitGuard: Fixing issues...',
            cancellable: false
        }, async () => {
            try {
                const result = execSync(
                    `gitguard fix "${workspaceFolder.uri.fsPath}" --apply`,
                    { encoding: 'utf-8', timeout: 60000 }
                );

                vscode.window.showInformationMessage('GitGuard: Fixes applied!');
                scanProject();
            } catch (error) {
                vscode.window.showErrorMessage(`GitGuard fix failed: ${error.message}`);
            }
        });
    }
}

async function explainFinding() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active editor');
        return;
    }

    const selection = editor.document.getText(editor.selection);
    if (!selection) {
        vscode.window.showWarningMessage('Select a rule ID to explain (e.g., SEC001)');
        return;
    }

    try {
        const result = execSync(
            `gitguard explain ${selection}`,
            { encoding: 'utf-8', timeout: 10000 }
        );

        const panel = vscode.window.createWebviewPanel(
            'gitguardExplain',
            `GitGuard: ${selection}`,
            vscode.ViewColumn.Beside,
            { enableScripts: false }
        );

        panel.webview.html = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px; }
                    h1 { color: #007acc; }
                    pre { background: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto; }
                </style>
            </head>
            <body>
                <h1>${selection}</h1>
                <pre>${result}</pre>
            </body>
            </html>
        `;
    } catch (error) {
        vscode.window.showErrorMessage(`Failed to explain: ${error.message}`);
    }
}

async function scanHistory() {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
        vscode.window.showWarningMessage('No workspace folder found');
        return;
    }

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'GitGuard: Scanning git history...',
        cancellable: true
    }, async (progress, token) => {
        try {
            const result = execSync(
                `gitguard history "${workspaceFolder.uri.fsPath}" --output /tmp/gitguard-history.json`,
                { encoding: 'utf-8', timeout: 120000 }
            );

            const findings = JSON.parse(
                require('fs').readFileSync('/tmp/gitguard-history.json', 'utf-8')
            );

            if (findings.length > 0) {
                vscode.window.showWarningMessage(
                    `GitGuard: Found ${findings.length} secrets in git history!`
                );
            } else {
                vscode.window.showInformationMessage(
                    'GitGuard: No secrets found in git history'
                );
            }
        } catch (error) {
            vscode.window.showErrorMessage(`GitGuard history scan failed: ${error.message}`);
        }
    });
}

function updateDiagnostics(findings) {
    const diagnostics = new Map();

    for (const finding of findings) {
        const uri = vscode.Uri.file(finding.file);
        if (!diagnostics.has(uri.toString())) {
            diagnostics.set(uri.toString(), []);
        }

        const range = new vscode.Range(
            new vscode.Position(finding.line - 1, 0),
            new vscode.Position(finding.line - 1, 1000)
        );

        const severity = mapSeverity(finding.severity);
        const diagnostic = new vscode.Diagnostic(
            range,
            `[${finding.rule}] ${finding.message}`,
            severity
        );

        diagnostic.source = 'GitGuard';
        diagnostic.code = finding.rule;

        diagnostics.get(uri.toString()).push(diagnostic);
    }

    for (const [uriString, diags] of diagnostics) {
        diagnosticCollection.set(vscode.Uri.parse(uriString), diags);
    }
}

function mapSeverity(severity) {
    switch (severity) {
        case 'critical':
        case 'high':
            return vscode.DiagnosticSeverity.Error;
        case 'medium':
            return vscode.DiagnosticSeverity.Warning;
        case 'low':
            return vscode.DiagnosticSeverity.Information;
        default:
            return vscode.DiagnosticSeverity.Hint;
    }
}

module.exports = {
    activate,
    deactivate
};
