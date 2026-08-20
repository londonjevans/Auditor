---
license: mit
library_name: transformers
base_model:
- deepseek-ai/DeepSeek-V3-Base
---

<p align="center">
  <img src="images/deep-cogito-logo.png" alt="Logo" width="40%">
</p>

# Cogito v2.1 - 671B MoE

[Blog Post](https://www.deepcogito.com/research/cogito-v2-1)

The Cogito v2.1 LLMs are instruction tuned generative models. All models are released under an open license for commercial use.

- Cogito v2.1 models are hybrid reasoning models. Each model can answer directly (standard LLM), or self-reflect before answering (like reasoning models).
- The LLMs are trained using **Iterated Distillation and Amplification (IDA)** - an scalable and efficient alignment strategy for superintelligence using iterative self-improvement.
- The models have been optimized for coding, STEM, instruction following and general helpfulness, and have significantly higher multilingual, coding and tool calling capabilities than size equivalent counterparts.
  - In both standard and reasoning modes, Cogito v2.1 models outperform their size equivalent counterparts on common industry benchmarks. 
- This model is trained in over 30 languages and supports a context length of 128k.

# Evaluations
Here is the model performance on some standard industry benchmarks:

<p align="left">
  <img src="images/v2-1-benchmark-1.png" alt="v2-1-benchmark-1" width="90%">
</p>

<p align="left">
  <img src="images/v2-1-benchmark-2.png" alt="v2-1-benchmark-2" width="90%">
</p>

<p align="left">
  <img src="images/v2-1-benchmark-3.png" alt="v2-1-benchmark-3" width="90%">
</p>

For detailed evaluations, please refer to the [Blog Post](https://www.deepcogito.com/research/cogito-v2-1). 

# Usage

This checkpoint is a 671B parameter Mixture of Experts model in BF16 format, consuming approximately 1.3 TB for parameters. You will need at least 8 B200s (1 node) or 16 H200s (2 nodes) to run this model. For serving on 8 H200s, use the quantized version: `deepcogito/cogito-671b-v2.1-FP8-Dynamic`.

To download and cache the model:
```bash
pip install transformers hf_transfer accelerate vllm
hf download deepcogito/cogito-671b-v2.1
```

### With HuggingFace pipeline

```python
import torch
from transformers import pipeline

model_id = "deepcogito/cogito-671b-v2.1"
pipe = pipeline("text-generation", model=model_id, model_kwargs={"dtype": "auto"}, device_map="auto")

messages = [
    {"role": "system", "content": "Always respond in 1-2 words."},
    {"role": "user", "content": "Who created you?"},
]

## without reasoning
outputs = pipe(messages, max_new_tokens=512, tokenizer_encode_kwargs={"enable_thinking": False})
print(outputs[0]["generated_text"][-1])
# {'role': 'assistant', 'content': 'Deep Cogito'}

## with reasoning
outputs = pipe(messages, max_new_tokens=512, tokenizer_encode_kwargs={"enable_thinking": True})
print(outputs[0]["generated_text"][-1])
# {'role': 'assistant', 'content': 'The question is asking about my creator. I know that I\'m Cogito, an AI assistant created by Deep Cogito, which is an AI research lab. The question is very direct and can be answered very briefly. Since the user has specified to always respond in 1-2 words, I should keep my answer extremely concise.\n\nThe most accurate 2-word answer would be "Deep Cogito" - this names the organization that created me without any unnecessary details. "Deep Cogito" is two words, so it fits the requirement perfectly.\n</think>\nDeep Cogito'}
```

### With HuggingFace AutoModel

```python
from transformers import AutoModelForCausalLM, AutoTokenizer

model_name = "deepcogito/cogito-671b-v2.1"

model = AutoModelForCausalLM.from_pretrained(model_name, torch_dtype="auto", device_map="auto")
tokenizer = AutoTokenizer.from_pretrained(model_name)

messages = [
    {"role": "system", "content": "Always respond in 1-2 words."},
    {"role": "user", "content": "Who created you?"}
]

text = tokenizer.apply_chat_template(
    messages,
    tokenize=False,
    add_generation_prompt=True,
    enable_thinking=False,
)
# To enable self-reflection or reasoning, set `enable_thinking=True` above.

model_inputs = tokenizer([text], return_tensors="pt").to(model.device)

generated_ids = model.generate(**model_inputs, max_new_tokens=512)
generated_ids = [
    output_ids[len(input_ids):] for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
]
response = tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
print(response)
```

### Tool Calling with HuggingFace

Cogito models support tool calling (single, parallel, multiple and parallel_multiple) both in standard and extended thinking mode.

```python
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

model_id = "deepcogito/cogito-671b-v2.1"

model = AutoModelForCausalLM.from_pretrained(model_id, dtype="auto", device_map="auto")
tokenizer = AutoTokenizer.from_pretrained(model_id)

def get_current_temperature(location: str) -> float:
    """
    Get the current temperature at a location.
    
    Args:
        location: The location to get the temperature for, in the format "City, Country"
    Returns:
        The current temperature at the specified location in the specified units, as a float.
    """
    return 22.

def generate(messages):
    global tokenizer, model
    prompt = tokenizer.apply_chat_template(
        messages,
        tools=[get_current_temperature],
        tokenize=False,
        add_generation_prompt=True,
        enable_thinking=False,
    )
    # To enable self-reflection or reasoning, set `enable_thinking=True` above.

    model_inputs = tokenizer(prompt, return_tensors="pt", add_special_tokens=False).to(model.device)

    generated_ids = model.generate(**model_inputs, max_new_tokens=512)
    generated_ids = [output_ids[len(input_ids):] for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)]
    response = tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
    return response

messages = [{"role": "user", "content": "whats the temperature in Paris?"}]
response = generate(messages)
```

This will result in the output -

```
<｜tool▁calls▁begin｜><｜tool▁call▁begin｜>function<｜tool▁sep｜>get_current_temperature
```json
{"location":"Paris, France"}
```<｜tool▁call▁end｜><｜tool▁calls▁end｜><｜end▁of▁sentence｜>
```

You can then generate text from this input as normal. If the model generates a tool call, you should add it to the chat like so:

```python
tool_call = {"name": "get_current_temperature", "arguments": {"location": "Paris, France"}}
messages.append({"role": "assistant", "tool_calls": [{"type": "function", "function": tool_call}]})
```

and then call the tool and append the result, with the tool role, and After that, you can generate() again to let the model use the tool result in the chat:

```python
messages.append({"role": "tool", "name": "get_current_temperature", "content": "22.0"})
response = generate(messages)
```

This should result in the string -
```
The current temperature in Paris is 22.0 degrees.<｜end▁of▁sentence｜>
```

### With vLLM

```python
from transformers import AutoTokenizer
from vllm import SamplingParams, LLM

model_id = "deepcogito/cogito-671b-v2.1"
tokenizer = AutoTokenizer.from_pretrained(model_id)
llm = LLM(model=model_id, tensor_parallel_size=8, gpu_memory_utilization=0.95, max_model_len=16384)
sampling_params = SamplingParams(temperature=0.6, max_tokens=8192)

prompts = ["who created you?", "how are you doing?"]

prompts = [
    tokenizer.apply_chat_template(
        [{"role": "system", "content": "Always respond in 1-2 words."}, {"role": "user", "content": prompt}],
        tokenize=False,
        add_generation_prompt=True,
        enable_thinking=False,
    )
    for prompt in prompts
]
# To enable self-reflection or reasoning, set `enable_thinking=True` above.

out = llm.generate(prompts, sampling_params=sampling_params)
print([res.outputs[0].text for res in out])
```

### Tool Calling with vLLM

```python
from vllm import LLM, SamplingParams


def get_current_temperature(location: str) -> float:
    """
    Get the current temperature at a location.
    
    Args:
        location: The location to get the temperature for, in the format "City, Country"
    Returns:
        The current temperature at the specified location in the specified units, as a float.
    """
    return 22. # A real function should probably actually get the temperature!


model_id = "deepcogito/cogito-671b-v2.1"

llm = LLM(model=model_id, gpu_memory_utilization=0.9, tensor_parallel_size=8, max_model_len=16384)
sampling_params = SamplingParams(temperature=0.6, max_tokens=512)

tokenizer = llm.get_tokenizer()

def generate_output(messages):
    global tokenizer, llm, sampling_params
    prompt = tokenizer.apply_chat_template(
        messages,
        tools=[get_current_temperature],
        tokenize=False,
        add_generation_prompt=True,
        enable_thinking=False,
    )
    response = llm.generate(prompt, sampling_params)
    return response[0].outputs[0].text

messages = [{"role": "user", "content": "whats the temperature today?"}]
response = generate_output(messages)
print(response)
# 'I\'d be happy to check the temperature for you. Could you please let me know which location you\'re interested in? Please provide the city and country (e.g., "New York, USA").'

messages.append({"role": "assistant", "content": 'I\'d be happy to check the temperature for you. Could you please let me know which location you\'re interested in? Please provide the city and country (e.g., "New York, USA").'})
messages.append({"role": "user", "content": "I live in San Francisco."})

response = generate_output(messages)
print(response)
# '<|tool▁calls▁begin|><|tool▁call▁begin|>function<|tool▁sep|>get_current_temperature<|tool▁sep|>{"location": "San Francisco, USA"}<|tool▁call▁end|><|tool▁calls▁end|>'

tool_calls = [{"type": "function", "function": {"name": "get_current_temperature", "arguments": {"location": "San Francisco, USA"}}}]
messages.append({"role": "assistant", "tool_calls": tool_calls})

messages.append({"role": "tool", "name": "get_current_temperature", "content": "22.0"})
response = generate_output(messages)
print(response)
# The current temperature in San Francisco, USA is 22°C.
```

**NOTE: We initiate the response with "\<think\>\n" at the beginning of every output when thinking is enabled. This is because hybrid models can be brittle at times, and adding a "\<think\>\n" ensures that the model does indeed respect thinking.**

## License
This repository and the model weights are licensed under **MIT License**.

## Contact
If you would like to reach out to our team, send an email to [contact@deepcogito.com](contact@deepcogito.com).