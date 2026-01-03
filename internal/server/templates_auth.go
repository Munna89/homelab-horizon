package server

const loginTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Homelab Horizon</title>
    <style>` + baseCSS + `
    .login-container { max-width: 400px; margin: 4rem auto; text-align: center; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Homelab Horizon</h1>
        <div class="card">
            {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
            <form method="POST" action="/auth">
                <input type="text" name="token" placeholder="Enter token" autofocus required>
                <button type="submit">Continue</button>
            </form>
        </div>
    </div>
</body>
</html>`
