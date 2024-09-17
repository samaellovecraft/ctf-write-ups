from flask import Blueprint, render_template, request, flash, url_for, redirect
from .report_utils import *
from blueprints.auth.auth_utils import deserialize_user_data
from blueprints.auth.auth_utils import admin_required, login_required


report_bp = Blueprint("report", __name__, subdomain="report")

@report_bp.route("/", methods=["GET"])
def report_index(): 
    return render_template("report/index.html")

@report_bp.route("/report_bug", methods=["GET", "POST"]) 
@login_required
def report_bug():
    if request.method == "POST":
        user_data = request.cookies.get("user_data")
        user_info = deserialize_user_data(user_data)
        name = user_info["username"]
        report_title = request.form["report_title"]
        description = request.form["description"] 
        if add_report(name, report_title, description):
            flash( "Bug report submitted successfully! Our team will be checking on this shortly.", "success", )
        else:
            flash("Error occured while trying to add the report!", "error")
            return redirect(url_for("report.report_bug"))
    return render_template("report/report_bug_form.html")


@report_bp.route("/list_reports")
@login_required
@admin_required
def list_reports():
    reports = get_all_reports()
    return render_template("report/report_list.html", reports=reports)

@report_bp.route("/report/")
@login_required
@admin_required
def report_details(report_id):
    report = get_report_by_id(report_id)
    print(report)
    if report:
        return render_template("report/report_details.html", report=report)
    else:
        flash("Report not found!", "error")
        return redirect(url_for("report.report_index"))

@report_bp.route("/about_reports", methods=["GET"])
def about_reports():
    return render_template("report/about_reports.html")
