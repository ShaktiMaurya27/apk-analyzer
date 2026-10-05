import sys
import argparse
from apk_analyzer.pipeline import APKAnalysisPipeline
from apk_analyzer.ingestion import APKIngestionError

def main():
    parser = argparse.ArgumentParser(description="Android APK Static Security Analysis Engine")
    parser.add_argument("apk_path", help="Path to the target Android APK file")
    parser.add_argument("-o", "--output", help="Optional path to save output JSON report", default=None)

    args = parser.parse_args()

    try:
        pipeline = APKAnalysisPipeline(args.apk_path)
        json_report = pipeline.run_json(indent=2)
        
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_report)
            print(f"[+] Security Analysis Report successfully saved to: {args.output}")
        else:
            print(json_report)

    except APKIngestionError as e:
        print(f"[-] APK Ingestion Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected Analysis Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
