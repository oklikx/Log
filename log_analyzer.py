#!/usr/bin/env python3
"""Скрипт анализа файлов access.log.

Собирает статистику по HTTP-запросам за один проход по файлу:
- общее количество запросов;
- количество запросов по HTTP-методам;
- топ-N IP-адресов по числу запросов;
- топ-N самых долгих запросов.

Результат выводится в терминал и сохраняется в JSON-файл
отдельно для каждого проанализированного лога.
"""

import argparse
import heapq
import json
import os
import re
import sys
from collections import Counter
from typing import Dict, List, Tuple


# Регулярка для разбора строки лога:
# %h - - %t "%r" %s %b "%{Referer}" "%{User-Agent}" %d
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<request>(?:[^"\\]|\\.)*)" '
    r'(?P<status>\d+) '
    r'(?P<bytes>\S+) '
    r'"(?P<referer>(?:[^"\\]|\\.)*)" '
    r'"(?P<user_agent>(?:[^"\\]|\\.)*)" '
    r'(?P<duration>\d+)'
)

HTTP_METHODS: Tuple[str, ...] = (
    'GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD',
)
TOP_N = 3


def parse_request(request: str) -> Tuple[str, str]:
    """Разбирает строку запроса на (метод, URL).

    Если строка не содержит URL — возвращает '-' в качестве URL.
    """
    parts = request.split()
    method = parts[0] if parts else '-'
    url = parts[1] if len(parts) > 1 else '-'
    return method, url


def analyze_file(filepath: str) -> Dict:
    """Собирает статистику по одному лог-файлу за один проход.

    Возвращает словарь со статистикой, пригодный для сериализации в JSON.
    """
    total = 0
    methods: Counter = Counter({m: 0 for m in HTTP_METHODS})
    ip_counter: Counter = Counter()

    # min-heap из TOP_N самых долгих запросов:
    # (duration, method, url, ip, time)
    slowest: List[Tuple[int, str, str, str, str]] = []

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line:
                continue

            match = LOG_PATTERN.match(line)
            if not match:
                continue

            total += 1
            ip = match.group('ip')
            method, url = parse_request(match.group('request'))
            duration = int(match.group('duration'))
            time_str = match.group('time')

            if method in methods:
                methods[method] += 1

            ip_counter[ip] += 1

            heapq.heappush(slowest, (duration, method, url, ip, time_str))
            if len(slowest) > TOP_N:
                heapq.heappop(slowest)

    # Из min-heap достаём TOP_N самых долгих в порядке убывания
    slowest_sorted = sorted(slowest, reverse=True)
    slowest_requests = [
        {
            'method': method,
            'url': url,
            'ip': ip,
            'duration': duration,
            'time': time_str,
        }
        for duration, method, url, ip, time_str in slowest_sorted
    ]

    top_ips = [
        {'ip': ip, 'count': count}
        for ip, count in ip_counter.most_common(TOP_N)
    ]

    return {
        'file': filepath,
        'total_requests': total,
        'methods': dict(methods),
        'top_ips': top_ips,
        'slowest_requests': slowest_requests,
    }


def print_stats(stats: Dict) -> None:
    """Печатает статистику по одному файлу в терминал."""
    print(f"\n{'=' * 60}")
    print(f"Файл: {stats['file']}")
    print(f"{'=' * 60}")
    print(f"Общее количество запросов: {stats['total_requests']}")

    print("\nЗапросы по HTTP-методам:")
    for method in HTTP_METHODS:
        print(f"  {method} - {stats['methods'].get(method, 0)}")

    print(f"\nТоп-{TOP_N} IP адресов:")
    for i, item in enumerate(stats['top_ips'], 1):
        print(f"  {i}. {item['ip']} — {item['count']} запросов")

    print(f"\nТоп-{TOP_N} самых долгих запросов:")
    for i, req in enumerate(stats['slowest_requests'], 1):
        print(f"  {i}. {req['method']} {req['url']}")
        print(
            f"     IP: {req['ip']}, "
            f"длительность: {req['duration']} мс, "
            f"время: {req['time']}"
        )
    print()


def save_json(stats: Dict, output_dir: str) -> None:
    """Сохраняет статистику в JSON-файл в указанной директории."""
    base = os.path.basename(stats['file'])
    name, _ = os.path.splitext(base)
    out_path = os.path.join(output_dir, f"{name}_stats.json")
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(f"Статистика сохранена: {out_path}")


def collect_log_files(path: str) -> List[str]:
    """Возвращает список файлов для анализа.

    Если передан файл — возвращает его в списке из одного элемента.
    Если передана директория — возвращает полные пути ко всем файлам внутри.
    """
    if os.path.isfile(path):
        return [path]
    if os.path.isdir(path):
        return [
            os.path.join(path, name)
            for name in os.listdir(path)
            if os.path.isfile(os.path.join(path, name))
        ]
    raise FileNotFoundError(f"Путь не найден: {path}")


def main() -> None:
    """Точка входа: разбирает аргументы и запускает анализ."""
    parser = argparse.ArgumentParser(
        description='Анализ access.log: сбор статистики по HTTP-запросам.'
    )
    parser.add_argument(
        'path',
        help='Путь к лог-файлу или директории с логами',
    )
    parser.add_argument(
        '-o', '--output',
        default=None,
        help='Директория для сохранения JSON (по умолчанию — рядом с логом)',
    )
    args = parser.parse_args()

    try:
        files = collect_log_files(args.path)
    except FileNotFoundError as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        sys.exit(1)

    if not files:
        print("Файлы для анализа не найдены.", file=sys.stderr)
        sys.exit(1)

    for filepath in files:
        stats = analyze_file(filepath)
        print_stats(stats)

        out_dir: str = args.output or os.path.dirname(
            os.path.abspath(filepath))
        os.makedirs(out_dir, exist_ok=True)
        save_json(stats, out_dir)


if __name__ == '__main__':
    main()
