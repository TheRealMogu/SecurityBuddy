from app import app
import routes  # noqa: F401

# For Vercel deployment
application = app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
