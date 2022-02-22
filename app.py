from flask import Flask, render_template, request, flash, redirect,url_for
import main, csv, os,json
app = Flask(__name__)
app.secret_key = "errr_hi"

@app.route("/")
def index():
	return render_template("index.html")

@app.route("/results", methods=["POST","GET"])
def results():
	folders=[]
	for folder in os.listdir('scans'):
		folders.append(folder)
	return render_template("results.html",folders=folders)

@app.route("/results/<folder>", methods=["POST","GET"])
def result(folder):
	names=[]
	if request.method=="POST":
		try:
			for name in os.listdir('scans/'+folder+'/outputs/dfs'):
				names.append(name.strip("_out.csv"))
				file = request.form["file"]
				with open('scans/'+folder+'/outputs/dfs/'+file+"_out.csv",newline='') as f:
					output =list(csv.reader(f))
			return render_template("result.html",name=names,results=output, folder=folder)
		except:
			for name in os.listdir('scans/'+folder+'/outputs/dfs'):
				names.append(name.strip("_out.csv"))
			return render_template("result.html",name=names, folder=folder)
	else:
		redirect("/results")

@app.route("/presets", methods= ["POST","GET"])
def presets():
	presets=json.load(open("presets.txt"))
	if request.method== "POST":
		user_input = request.form["user_input"].split(":")
		number ="preset"+str(len(presets)+1)
		presets.update({number:{user_input[0]:(" ").join(user_input[1:])}})
		json.dump(presets, open("presets.txt",'w'))
		presets=json.load(open("presets.txt"))
	return render_template("presets.html", presets=presets)

@app.route('/delete/<preset>')
def delete(preset):
	presets=json.load(open("presets.txt"))
	presets.pop(preset)
	json.dump(presets, open("presets.txt",'w'))
	return redirect("/presets")

@app.route('/update/<preset>', methods=["POST","GET"])
def update(preset):
	presets=json.load(open("presets.txt"))
	if request.method == "POST":
		user_input = request.form["user_input"].split(":")
		presets[preset]["Name"] = user_input[0]
		presets[preset]["Details"] = user_input[1]
		json.dump(presets, open("presets.txt",'w'))
		return redirect("/presets")
	else:
		return render_template("update.html", preset=presets[preset]['Name']+":"+presets[preset]['Details'])

@app.route("/scan", methods=["POST","GET"])
def scan():
	if request.method == "POST":
		return redirect("start")
	else:
		presets=json.load(open("presets.txt"))
		return render_template("scan.html",presets=presets)

@app.route("/scan/custom", methods=["POST","GET"])
def custom():
	return render_template("custom.html")

@app.route("/start", methods=["POST","GET"])
def start():
	if request.method == "POST":
		ip = request.form["ip"]
		try:
			depth =request.form["depth"]
			input = ip+" "+depth
			main.start(input)
			return render_template("start.html")
		except:
			presets=json.load(open("presets.txt"))
			for preset in presets:
				if ip in presets[preset]["Name"]:
					ip =presets[preset]["Details"]
					main.start(ip)
					return render_template("start.html")
		flags = request.form["flag"]
		input = ip+" "+flags
		main.start(input)
		return render_template("start.html")
	else:
		return f"The URL /start has been accessed directly. Try going to '/scan' to start a scan"

if __name__=="__main__":
    app.run(debug=True)
