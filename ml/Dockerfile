# One image for both the scoring service (target) and the training job (host),
# so the model is always trained and loaded with the same scikit-learn version.
FROM python:3.12-slim

WORKDIR /app
# TRAIN=1 adds pandas + mlflow for the training image; the scoring service on the target stays lean
ARG TRAIN=0
COPY requirements.txt requirements-train.txt ./
RUN pip install --no-cache-dir -r $( [ "$TRAIN" = 1 ] && echo requirements-train.txt || echo requirements.txt )

COPY lab_ml/ lab_ml/
COPY service/ service/
COPY pipeline/ pipeline/

RUN useradd --system --uid 10001 ml
USER ml

ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "service.app:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "/app"]
