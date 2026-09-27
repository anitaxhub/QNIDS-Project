from gui.ai_analyzer import AIAnalyzer
import time

def show_result(result):
    print("\n--- Groq Response ---")
    print(result)
    print("---------------------")

print("AIAnalyzer initialize ho raha hai...")
analyzer = AIAnalyzer()
print("✅ Key load ho gayi, API call kar raha hun...\n")

analyzer.analyze(
    attack_info="SYN Flood",
    ip="192.168.1.100",
    confidence=87,
    protocol="TCP",
    src_bytes=5000,
    duration=2,
    count=500,
    serror_rate=0.9,
    callback=show_result
)

# Thread ko kaam karne ka waqt do
time.sleep(10)
print("\n✅ Test complete!")