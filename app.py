from flask import Flask, render_template, request, flash, redirect,url_for
import main, csv, os,json
app = Flask(__name__)
app.secret_key = "errr_hi"

@app.route("/")
def index():
	try:
		return render_template("index.html")
	except:
		flash("An error occurred please try again.")
		return render_template("error.html")

@app.route("/results", methods=["POST","GET"])
def results():
	try:
		if request.method=="POST":
			input = request.form["name"]
			main.reporting(input)
		folders=[]
		for folder in os.listdir('scans'):
			folders.append(folder)
		return render_template("results.html",folders=folders)
	except:
		flash("An error occurred please try again.")
		return render_template("error.html")

@app.route("/results/<folder>", methods=["POST","GET"])
def result(folder):
	try:
		if request.method=="POST":
			names=[]
			try:
				for name in os.listdir('scans/'+folder+'/outputs/dfs'):
					names.append(name.strip("_out.csv"))
					file = request.form["file"]
					with open('scans/'+folder+'/outputs/dfs/'+file+"_out.csv",newline='') as f:
						output =list(csv.reader(f))
						output.pop(0)
				return render_template("result.html",name=names,results=output, folder=folder, file=file)
			except:
				for name in os.listdir('scans/'+folder+'/outputs/dfs'):
					names.append(name.strip("_out.csv"))
				return render_template("result.html",name=names, folder=folder)
		else:
			redirect("/results")
	except:
		flash("An error occurred please try again.")
		return render_template("error.html")

@app.route("/presets", methods= ["POST","GET"])
def presets():
	try:
		presets=json.load(open("presets.txt"))
		if request.method== "POST":
			user_input = request.form["user_input"].split(":")
			number ="preset"+str(len(presets)+1)
			presets.update({number:{'Name':user_input[0],'Details':(" ").join(user_input[1:])}})
			json.dump(presets, open("presets.txt",'w'))
			presets=json.load(open("presets.txt"))
			return render_template("presets.html", presets=presets)
		else:
			return render_template("presets.html", presets=presets)
	except:
		flash("An error occurred, please try again.")
		return render_template("error.html")

@app.route('/delete/<preset>')
def delete(preset):
	try:
		presets=json.load(open("presets.txt"))
		presets.pop(preset)
		json.dump(presets, open("presets.txt",'w'))
		return redirect("/presets")
	except:
		flash("An error occurred please try again.")
		return render_template("error.html")

@app.route('/update/<preset>', methods=["POST","GET"])
def update(preset):
	try:
		presets=json.load(open("presets.txt"))
		if request.method == "POST":
				user_input = request.form["user_input"]
				user_input=str(user_input).split(":")
				presets[preset]["Name"] = user_input[0]
				presets[preset]["Details"] = user_input[1]
				json.dump(presets, open("presets.txt",'w'))
				return redirect("/presets")
		else:
			return render_template("update.html", preset=preset,details=presets[preset]['Name']+":"+presets[preset]['Details'])
	except:
		flash("Invalid user input, please try again.")
		return render_template("error.html")

@app.route("/scan", methods=["POST","GET"])
def scan():
	try:
		if request.method == "POST":
			return redirect("complete")
		else:
			presets=json.load(open("presets.txt"))
			return render_template("scan.html",presets=presets)
	except:
		flash("An error occurred please try again.")
		return render_template("error.html")

@app.route("/scan/custom", methods=["POST","GET"])
def custom():
	try:
		flags =["-A","-sL","-sn","-Pn","-PS","-PA","-PU","-PY","-PE","-PP","-PM","-n","-R","-sS","-sT","-sA","-sW","-sM","-sU","-sN","-sF","-sX","-sY","-sZ","-sO","-F","-r","-sV","--version-light","--version-all","--version-trace","-sC","-O","--osscan-limit","--osscan-guess","--min-rtt-timeout","--max-rtt-timeout","-f","-oN","-oX","-oS","-d"]
		return render_template("custom.html",flags=flags)
	except:
		flash("An error occurred please try again.")
		return render_template("error.html")

@app.route("/complete", methods=["POST","GET"])
def complete():
	if request.method == "POST":
		ip = request.form["ip"]
		try:
			depth =request.form["depth"]
			input = ip+" "+depth
			main.scan(input)
			return render_template("complete.html")
		except:
			presets=json.load(open("presets.txt"))
			for preset in presets:
				if ip in presets[preset]["Name"]:
					ip =presets[preset]["Details"]
					main.scan(ip)
					return render_template("complete.html")
		flags = request.form["flag"]
		input = ip+" "+flags
		main.scan(input)
		return render_template("complete.html")
	else:
		flash("The URL /complete has been accessed directly. Try going to '/scan' to start a scan")
		return render_template("error.html")

if __name__=="__main__":
    app.run(debug=True)
